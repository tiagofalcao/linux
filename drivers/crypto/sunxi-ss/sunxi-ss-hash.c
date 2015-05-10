/*
 * sunxi-ss-hash.c - hardware cryptographic accelerator for Allwinner A20 SoC
 *
 * Copyright (C) 2013-2015 Corentin LABBE <clabbe.montjoie@gmail.com>
 *
 * This file add support for MD5 and SHA1.
 *
 * You could find the datasheet in Documentation/arm/sunxi/README
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include "sunxi-ss.h"

/* This is a totaly arbitrary value */
#define SS_TIMEOUT 100

int sunxi_hash_crainit(struct crypto_tfm *tfm)
{
	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
			sizeof(struct sunxi_req_ctx));
	return 0;
}

/* sunxi_hash_init: initialize request context */
int sunxi_hash_init(struct ahash_request *areq)
{
	const char *hash_type;
	struct sunxi_req_ctx *op = ahash_request_ctx(areq);
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(areq);
	struct ahash_alg *alg = __crypto_ahash_alg(tfm->base.__crt_alg);
	struct sunxi_ss_alg_template *algt;
	struct sunxi_ss_ctx *ss;

	memset(op, 0, sizeof(struct sunxi_req_ctx));

	algt = container_of(alg, struct sunxi_ss_alg_template, alg.hash);
	ss = algt->ss;
	op->ss = algt->ss;

	hash_type = crypto_tfm_alg_name(areq->base.tfm);

	if (strcmp(hash_type, "sha1") == 0)
		op->mode = SS_OP_SHA1;
	else if (strcmp(hash_type, "md5") == 0)
		op->mode = SS_OP_MD5;
	else
		return -EINVAL;

	return 0;
}

int sunxi_hash_export(struct ahash_request *areq, void *out)
{
	struct sunxi_req_ctx *op = ahash_request_ctx(areq);

	memcpy(out, op, sizeof(struct sunxi_req_ctx));
	return 0;
}

int sunxi_hash_import(struct ahash_request *areq, const void *in)
{
	struct sunxi_req_ctx *op = ahash_request_ctx(areq);

	memcpy(op, in, sizeof(struct sunxi_req_ctx));
	return 0;
}

/*
 * sunxi_hash_update: update hash engine
 *
 * Could be used for both SHA1 and MD5
 * Write data by step of 32bits and put then in the SS.
 *
 * Since we cannot leave partial data and hash state in the engine,
 * we need to get the hash state at the end of this function.
 * After some work, I have found that we can get the hash state every 64 bytes
 *
 * So the first work is to get the number of bytes to write to SS modulo 64
 * The extra bytes will go to two different destination:
 * op->wait for full 32bits word
 * op->wb (waiting bytes) for partial 32 bits word
 * So we can have up to (64/4)-1 op->wait words and 0/1/2/3 bytes in wb
 *
 * So at the begin of update()
 * if op->nwait * 4 + areq->nbytes < 64
 * => all data will be writen to wait buffers and end=0
 * if not, write all nwait to the device and position end to complete to 64bytes
 *
 * example 1:
 * update1 60o => nwait=15
 * update2 60o => need one more word to have 64 bytes
 * end=4
 * so write all data in op->wait and one word of SGs
 * write remaining data in op->wait
 * final state op->nwait=14
 */
int sunxi_hash_update(struct ahash_request *areq)
{
	u32 v, ivmode = 0;
	unsigned int i = 0;
	/*
	 * i is the total bytes read from SGs, to be compared to areq->nbytes
	 * i is important because we cannot rely on SG length since the sum of
	 * SG->length could be greater than areq->nbytes
	 */

	struct sunxi_req_ctx *op = ahash_request_ctx(areq);
	struct sunxi_ss_ctx *ss = op->ss;
	struct scatterlist *in_sg;
	unsigned int in_i = 0; /* advancement in the current SG */
	u64 end;
	/*
	 * end is the position when we need to stop writing to the device,
	 * to be compared to i
	 * So end is always a multiple of 64
	 * if end = 0 all data must be kept for later use and no write
	 * on the device is done.
	 */
	int in_r, err = 0;
	void *src_addr;
	unsigned int todo;
	u32 spaces, rx_cnt;
	unsigned long flags = 0;

	dev_dbg(ss->dev, "%s %s bc=%llu len=%u mode=%x bw=%u ww=%u h0=%0x",
			__func__, crypto_tfm_alg_name(areq->base.tfm),
			op->byte_count, areq->nbytes, op->mode,
			op->nbw, op->nwait, op->hash[0]);

	if (areq->nbytes == 0)
		return 0;

	if (areq->nbytes + op->nwait * 4 + op->nbw < 64)
		end = 0;
	else
		end = ((areq->nbytes + op->nwait * 4 + op->nbw) / 64) * 64
			- op->nbw - op->nwait * 4;

	if (end > areq->nbytes || areq->nbytes - end > 63) {
		dev_err(ss->dev, "ERROR: Bound error %llu %u\n",
				end, areq->nbytes);
		return -EINVAL;
	}

	if (end > 0) {
		spin_lock_irqsave(&ss->slock, flags);

		/*
		 * if some data have been processed before,
		 * we need to restore the partial hash state
		 */
		if (op->byte_count > 0) {
			ivmode = SS_IV_ARBITRARY;
			for (i = 0; i < 5; i++)
				writel(op->hash[i], ss->base + SS_IV0 + i * 4);
		}
		/* Enable the device */
		writel(op->mode | SS_ENABLED | ivmode, ss->base + SS_CTL);
	}

	rx_cnt = 32;
	i = 0;

	if (op->nwait > 0 && end > 0) {
		/*
		 * a precedent update was done
		 * No test versus rx_cnt since op->nwait cannot be more than 15
		 */
		writesl(ss->base + SS_RXFIFO, op->wait, op->nwait);
		op->byte_count += 4 * op->nwait;
		op->nwait = 0;
	}

	in_sg = areq->src;
	src_addr = kmap(sg_page(in_sg)) + in_sg->offset;
	if (src_addr == NULL) {
		dev_err(ss->dev, "ERROR: Cannot kmap source buffer\n");
		err = -EFAULT;
		goto hash_update_release_ss;
	}
	do {
		/*
		 * step 1, if some bytes remains from last SG,
		 * try to complete them to 4 and send that word
		 */
		if (op->nbw > 0) {
			while (op->nbw < 4 && i < areq->nbytes &&
					in_i < in_sg->length) {
				op->wb |= (*(u8 *)(src_addr + in_i))
					<< (8 * op->nbw);
				dev_dbg(ss->dev, "%s: Complete w=%d wb=%x\n",
						__func__, op->nbw, op->wb);
				i++;
				in_i++;
				op->nbw++;
			}
			if (op->nbw == 4) {
				if (i <= end) {
					writel(op->wb, ss->base + SS_RXFIFO);
					rx_cnt--;
					if (rx_cnt > 0) {
						spaces = readl_relaxed(ss->base + SS_FCSR);
						rx_cnt = SS_RXFIFO_SPACES(spaces);
					}
					op->byte_count += 4;
				} else {
					op->wait[op->nwait] = op->wb;
					op->nwait++;
					dev_dbg(ss->dev, "%s: Keep %u bytes after %llu\n",
						__func__, op->nwait, end);
				}
				op->nbw = 0;
				op->wb = 0;
			}
		}
		/* step 2, main loop, read data 4bytes at a time */
		while (i < areq->nbytes && in_i < in_sg->length) {
			/* how many bytes we can read from current SG */
			in_r = min(in_sg->length - in_i, areq->nbytes - i);
			if (in_r < 4) {
				/* Not enough data to write to the device */
				op->wb = 0;
				while (in_r > 0) {
					op->wb |= (*(u8 *)(src_addr + in_i))
						<< (8 * op->nbw);
					dev_dbg(ss->dev, "%s: ending bw=%d wb=%x\n",
						__func__, op->nbw, op->wb);
					in_r--;
					i++;
					in_i++;
					op->nbw++;
				}
				goto nextsg;
			}
			v = *(u32 *)(src_addr + in_i);
			if (i < end) {
				todo = min3((u32)(end - i) / 4, rx_cnt, (u32)in_r / 4);
				writesl(ss->base + SS_RXFIFO, src_addr + in_i, todo);
				i += 4 * todo;
				in_i += 4 * todo;
				op->byte_count += 4 * todo;
				rx_cnt -= todo;
				if (rx_cnt == 0) {
					spaces = readl_relaxed(ss->base + SS_FCSR);
					rx_cnt = SS_RXFIFO_SPACES(spaces);
				}
			} else {
				op->wait[op->nwait] = v;
				i += 4;
				in_i += 4;
				op->nwait++;
				dev_dbg(ss->dev, "%s: Keep word ww=%u after %llu\n",
						__func__, op->nwait, end);
				if (op->nwait > 15) {
					dev_err(ss->dev, "FATAL: Cannot enqueue more, bug?\n");
					err = -EIO;
					goto hash_update_release_ss;
				}
			}
		}
nextsg:
		/* Nothing more to read in this SG */
		if (in_i == in_sg->length) {
			kunmap(sg_page(in_sg));
			do {
				in_sg = sg_next(in_sg);
			} while (in_sg != NULL && in_sg->length == 0);
			in_i = 0;
			if (in_sg != NULL) {
				src_addr = kmap(sg_page(in_sg)) + in_sg->offset;
				if (src_addr == NULL) {
					dev_err(ss->dev, "ERROR: Cannot kmap source buffer\n");
					err = -EFAULT;
					goto hash_update_release_ss;
				}
			}
		}
	} while (in_sg != NULL && i < areq->nbytes);

hash_update_release_ss:
	/* the device was not used, so nothing to release */
	if (end == 0)
		return err;

	if (err == 0) {
		/* ask the device to finish the hashing */
		writel(op->mode | SS_ENABLED | SS_DATA_END, ss->base + SS_CTL);
		i = 0;
		do {
			v = readl(ss->base + SS_CTL);
			i++;
		} while (i < SS_TIMEOUT && (v & SS_DATA_END) > 0);
		if (i >= SS_TIMEOUT) {
			dev_err(ss->dev, "ERROR: %s: hash end timeout after %d loop, CTL=%x\n",
					__func__, i, v);
			err = -EIO;
			goto hash_update_release_ss;
			/*
			 * this seems strange (to go backward)
			 * but since err is set, it works
			 * */
		}

		/* get the partial hash only if something was written */
		if (op->mode == SS_OP_SHA1) {
			for (i = 0; i < 5; i++)
				op->hash[i] = readl(ss->base + SS_MD0 + i * 4);
		} else {
			for (i = 0; i < 4; i++)
				op->hash[i] = readl(ss->base + SS_MD0 + i * 4);
		}
	}
	writel(0, ss->base + SS_CTL);
	spin_unlock_irqrestore(&ss->slock, flags);
	return err;
}

/*
 * sunxi_hash_final: finalize hashing operation
 *
 * If we have some remaining bytes, we write them.
 * Then ask the SS for finalizing the hashing operation
 *
 * I do not check RX FIFO size in this function since the size is 32
 * after each enabling and this function neither write more than 32 words.
 */
int sunxi_hash_final(struct ahash_request *areq)
{
	u32 v, ivmode = 0;
	unsigned int i;
	unsigned int j = 0;
	int zeros;
	unsigned int index, padlen;
	__be64 bits;
	struct sunxi_req_ctx *op = ahash_request_ctx(areq);
	struct sunxi_ss_ctx *ss = op->ss;
	u32 bf[32];
	unsigned long flags;

	dev_dbg(ss->dev, "%s: byte=%llu len=%u mode=%x bw=%u %x h=%x ww=%u",
			__func__, op->byte_count, areq->nbytes, op->mode,
			op->nbw, op->wb, op->hash[0], op->nwait);

	spin_lock_irqsave(&ss->slock, flags);

	/*
	 * if we have already writed something,
	 * restore the partial hash state
	 */
	if (op->byte_count > 0) {
		ivmode = SS_IV_ARBITRARY;
		for (i = 0; i < 5; i++)
			writel(op->hash[i], ss->base + SS_IV0 + i * 4);
	}
	writel(op->mode | SS_ENABLED | ivmode, ss->base + SS_CTL);

	/* write the remaining words of the wait buffer */
	if (op->nwait > 0) {
		writesl(ss->base + SS_RXFIFO, op->wait, op->nwait);
		op->byte_count += 4 * op->nwait;
		op->nwait = 0;
	}

	/* write the remaining bytes of the nbw buffer */
	if (op->nbw > 0) {
		op->wb |= ((1 << 7) << (op->nbw * 8));
		bf[j++] = op->wb;
	} else {
		bf[j++] = 1 << 7;
	}

	/*
	 * number of space to pad to obtain 64o minus 8(size) minus 4 (final 1)
	 * I take the operations from other md5/sha1 implementations
	 */

	/* we have already send 4 more byte of which nbw data */
	if (op->mode == SS_OP_MD5) {
		index = (op->byte_count + 4) & 0x3f;
		op->byte_count += op->nbw;
		if (index > 56)
			zeros = (120 - index) / 4;
		else
			zeros = (56 - index) / 4;
	} else {
		op->byte_count += op->nbw;
		index = op->byte_count & 0x3f;
		padlen = (index < 56) ? (56 - index) : ((64 + 56) - index);
		zeros = (padlen - 1) / 4;
	}

	/*for (i = 0; i < zeros; i++)
		bf[j++] = 0;*/
	memset(bf + j, 0, 4 * zeros);
	j += zeros;

	/* write the length of data */
	if (op->mode == SS_OP_SHA1) {
		bits = cpu_to_be64(op->byte_count << 3);
		bf[j++] = bits & 0xffffffff;
		bf[j++] = (bits >> 32) & 0xffffffff;
	} else {
		bf[j++] = (op->byte_count << 3) & 0xffffffff;
		bf[j++] = (op->byte_count >> 29) & 0xffffffff;
	}
	writesl(ss->base + SS_RXFIFO, bf, j);

	/* Tell the SS to stop the hashing */
	writel(op->mode | SS_ENABLED | SS_DATA_END, ss->base + SS_CTL);

	/*
	 * Wait for SS to finish the hash.
	 * The timeout could happend only in case of bad overcloking
	 * or driver bug.
	 */
	i = 0;
	do {
		v = readl(ss->base + SS_CTL);
		i++;
	} while (i < SS_TIMEOUT && (v & SS_DATA_END) > 0);
	if (i >= SS_TIMEOUT) {
		dev_err(ss->dev, "ERROR: hash end timeout %d>%d ctl=%x len=%u\n",
				i, SS_TIMEOUT, v, areq->nbytes);
		writel(0, ss->base + SS_CTL);
		spin_unlock_irqrestore(&ss->slock, flags);
		return -EIO;
	}

	/* Get the hash from the device */
	if (op->mode == SS_OP_SHA1) {
		for (i = 0; i < 5; i++) {
			v = cpu_to_be32(readl(ss->base + SS_MD0 + i * 4));
			memcpy(areq->result + i * 4, &v, 4);
		}
	} else {
		for (i = 0; i < 4; i++) {
			v = readl(ss->base + SS_MD0 + i * 4);
			memcpy(areq->result + i * 4, &v, 4);
		}
	}
	writel(0, ss->base + SS_CTL);
	spin_unlock_irqrestore(&ss->slock, flags);
	return 0;
}

/* sunxi_hash_finup: finalize hashing operation after an update */
int sunxi_hash_finup(struct ahash_request *areq)
{
	int err;

	err = sunxi_hash_update(areq);
	if (err != 0)
		return err;

	return sunxi_hash_final(areq);
}

/* combo of init/update/final functions */
int sunxi_hash_digest(struct ahash_request *areq)
{
	int err;

	err = sunxi_hash_init(areq);
	if (err != 0)
		return err;

	err = sunxi_hash_update(areq);
	if (err != 0)
		return err;

	return sunxi_hash_final(areq);
}
