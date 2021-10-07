/*
 * iplink_xdp.c XDP program loader
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Daniel Borkmann <daniel@iogearbox.net>
 */

#include <stdio.h>
#include <stdlib.h>

#include <linux/bpf.h>

#include "bpf_util.h"
#include "utils.h"
#include "ip_common.h"

extern int force;

struct xdp_req {
	struct iplink_req *req;
	__u32 flags;
};

static void xdp_ebpf_cb(void *raw, int fd, const char *annotation)
{
	struct xdp_req *xdp = raw;
	struct iplink_req *req = xdp->req;
	struct rtattr *xdp_attr;

	xdp_attr = addattr_nest(&req->n, sizeof(*req), IFLA_XDP);
	addattr32(&req->n, sizeof(*req), IFLA_XDP_FD, fd);
	if (xdp->flags)
		addattr32(&req->n, sizeof(*req), IFLA_XDP_FLAGS, xdp->flags);
	addattr_nest_end(&req->n, xdp_attr);
}

static const struct bpf_cfg_ops bpf_cb_ops = {
	.ebpf_cb = xdp_ebpf_cb,
};

static int xdp_delete(struct xdp_req *xdp)
{
	xdp_ebpf_cb(xdp, -1, NULL);
	return 0;
}

int xdp_parse(int *argc, char ***argv, struct iplink_req *req,
	      const char *ifname, bool generic, bool drv, bool offload)
{
	struct bpf_cfg_in cfg = {
		.type = BPF_PROG_TYPE_XDP,
		.argc = *argc,
		.argv = *argv,
	};
	struct xdp_req xdp = {
		.req = req,
	};

	if (offload) {
		int ifindex = ll_name_to_index(ifname);

		if (!ifindex)
			incomplete_command();
		cfg.ifindex = ifindex;
	}

	if (!force)
		xdp.flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;
	if (generic)
		xdp.flags |= XDP_FLAGS_SKB_MODE;
	if (drv)
		xdp.flags |= XDP_FLAGS_DRV_MODE;
	if (offload)
		xdp.flags |= XDP_FLAGS_HW_MODE;

	if (*argc == 1) {
		if (strcmp(**argv, "none") == 0 ||
		    strcmp(**argv, "off") == 0)
			return xdp_delete(&xdp);
	}

	if (bpf_parse_and_load_common(&cfg, &bpf_cb_ops, &xdp))
		return -1;

	*argc = cfg.argc;
	*argv = cfg.argv;
	return 0;
}

static void xdp_dump_json_one(struct rtattr *tb[IFLA_XDP_MAX + 1], __u32 attr,
			      __u8 mode)
{
	if (!tb[attr])
		return;

	open_json_object(NULL);
	print_uint(PRINT_JSON, "mode", NULL, mode);
	bpf_dump_prog_info(NULL, rta_getattr_u32(tb[attr]));
	close_json_object();
}

static void xdp_dump_json(struct rtattr *tb[IFLA_XDP_MAX + 1])
{
	__u32 prog_id = 0;
	__u8 mode;

	mode = rta_getattr_u8(tb[IFLA_XDP_ATTACHED]);
	if (tb[IFLA_XDP_PROG_ID])
		prog_id = rta_getattr_u32(tb[IFLA_XDP_PROG_ID]);

	open_json_object("xdp");
	print_uint(PRINT_JSON, "mode", NULL, mode);
	if (prog_id)
		bpf_dump_prog_info(NULL, prog_id);

	open_json_array(PRINT_JSON, "attached");
	if (tb[IFLA_XDP_SKB_PROG_ID] ||
	    tb[IFLA_XDP_DRV_PROG_ID] ||
	    tb[IFLA_XDP_HW_PROG_ID]) {
		xdp_dump_json_one(tb, IFLA_XDP_SKB_PROG_ID, XDP_ATTACHED_SKB);
		xdp_dump_json_one(tb, IFLA_XDP_DRV_PROG_ID, XDP_ATTACHED_DRV);
		xdp_dump_json_one(tb, IFLA_XDP_HW_PROG_ID, XDP_ATTACHED_HW);
	} else if (tb[IFLA_XDP_PROG_ID]) {
		/* Older kernel - use IFLA_XDP_PROG_ID */
		xdp_dump_json_one(tb, IFLA_XDP_PROG_ID, mode);
	}
	close_json_array(PRINT_JSON, NULL);

	close_json_object();
}

static void xdp_dump_prog_one(FILE *fp, struct rtattr *tb[IFLA_XDP_MAX + 1],
			      __u32 attr, bool link, bool details,
			      const char *pfx)
{
	__u32 prog_id;

	if (!tb[attr])
		return;

	prog_id = rta_getattr_u32(tb[attr]);
	if (!details) {
		if (prog_id && !link && attr == IFLA_XDP_PROG_ID)
			fprintf(fp, "/id:%u", prog_id);
		return;
	}

	if (prog_id) {
		fprintf(fp, "%s    prog/xdp%s ", _SL_, pfx);
		bpf_dump_prog_info(fp, prog_id);
	}
}

void xdp_dump(FILE *fp, struct rtattr *xdp, bool link, bool details)
{
	struct rtattr *tb[IFLA_XDP_MAX + 1];
	__u8 mode;

	parse_rtattr_nested(tb, IFLA_XDP_MAX, xdp);

	if (!tb[IFLA_XDP_ATTACHED])
		return;

	mode = rta_getattr_u8(tb[IFLA_XDP_ATTACHED]);
	if (mode == XDP_ATTACHED_NONE)
		return;
	else if (is_json_context())
		return details ? (void)0 : xdp_dump_json(tb);
	else if (details && link)
		/* don't print mode */;
	else if (mode == XDP_ATTACHED_DRV)
		fprintf(fp, "xdp");
	else if (mode == XDP_ATTACHED_SKB)
		fprintf(fp, "xdpgeneric");
	else if (mode == XDP_ATTACHED_HW)
		fprintf(fp, "xdpoffload");
	else if (mode == XDP_ATTACHED_MULTI)
		fprintf(fp, "xdpmulti");
	else
		fprintf(fp, "xdp[%u]", mode);

	xdp_dump_prog_one(fp, tb, IFLA_XDP_PROG_ID, link, details, "");

	if (mode == XDP_ATTACHED_MULTI) {
		xdp_dump_prog_one(fp, tb, IFLA_XDP_SKB_PROG_ID, link, details,
				  "generic");
		xdp_dump_prog_one(fp, tb, IFLA_XDP_DRV_PROG_ID, link, details,
				  "drv");
		xdp_dump_prog_one(fp, tb, IFLA_XDP_HW_PROG_ID, link, details,
				  "offload");
	}

	if (!details || !link)
		fprintf(fp, " ");
}

struct xdp_stats_ctx {
	FILE		*fp;
	__u32		flt_if;
	__u32		flt_type;
	__u32		cur_if;
	__u32		saved_if;
	__u32		saved_type;
	__u32		saved_ch;
};

static const char * const xdp_stats_types[] = {
	[IFLA_XDP_XSTATS_TYPE_XDP]		= "xdp",
	[IFLA_XDP_XSTATS_TYPE_XSK]		= "xsk",
};

static const char * const xdp_stats_fields[] = {
	[IFLA_XDP_XSTATS_PACKETS]		= "rx_xdp_packets",
	[IFLA_XDP_XSTATS_BYTES]			= "rx_xdp_bytes",
	[IFLA_XDP_XSTATS_ERRORS]		= "rx_xdp_errors",
	[IFLA_XDP_XSTATS_ABORTED]		= "rx_xdp_aborted",
	[IFLA_XDP_XSTATS_DROP]			= "rx_xdp_drop",
	[IFLA_XDP_XSTATS_INVALID]		= "rx_xdp_invalid",
	[IFLA_XDP_XSTATS_PASS]			= "rx_xdp_pass",
	[IFLA_XDP_XSTATS_REDIRECT]		= "rx_xdp_redirect",
	[IFLA_XDP_XSTATS_REDIRECT_ERRORS]	= "rx_xdp_redirect_errors",
	[IFLA_XDP_XSTATS_TX]			= "rx_xdp_tx",
	[IFLA_XDP_XSTATS_TX_ERRORS]		= "rx_xdp_tx_errors",
	[IFLA_XDP_XSTATS_XMIT_PACKETS]		= "tx_xdp_xmit_packets",
	[IFLA_XDP_XSTATS_XMIT_BYTES]		= "tx_xdp_xmit_bytes",
	[IFLA_XDP_XSTATS_XMIT_ERRORS]		= "tx_xdp_xmit_errors",
	[IFLA_XDP_XSTATS_XMIT_FULL]		= "tx_xdp_xmit_full",
};

static void xdp_stats_cleanup_ctx(const struct xdp_stats_ctx *ctx, bool ifobj)
{
	if (ctx->saved_ch)
		close_json_array(PRINT_JSON, NULL);

	if (ctx->saved_type >= IFLA_XDP_XSTATS_TYPE_START)
		close_json_object();

	if (ifobj && ctx->saved_if) {
		close_json_object();
		fflush(ctx->fp);
	}
}

static int xdp_stats_print_one(FILE *fp, const struct rtattr *attr,
			       const char *typestr, const char *chstr)
{
	struct rtattr *tb[__IFLA_XDP_XSTATS_CNT];
	__u32 i;

	parse_rtattr_nested(tb, IFLA_XDP_XSTATS_MAX, attr);

	for (i = IFLA_XDP_XSTATS_START; i < __IFLA_XDP_XSTATS_CNT; i++) {
		const char *stat = xdp_stats_fields[i];

		if (!stat) {
			fprintf(stderr, "Unknown XDP statistics field %u\n",
				i);
			return -1;
		}

		if (!is_json_context()) {
			fprintf(fp, "%s-", typestr);

			if (chstr)
				fprintf(fp, "%s-", chstr);

			fprintf(fp, "%s: ", stat);
		}

		print_u64(PRINT_ANY, stat, "%llu\n", rta_getattr_u64(tb[i]));
	}

	return 0;
}

static int xdp_stats_print_xdpxsk(struct xdp_stats_ctx *ctx,
				  const struct rtattr *attr,
				  const char *typestr)
{
	__u32 ch = ctx->saved_ch;
	struct rtattr *i;
	int rem, ret;

	for (i = RTA_DATA(attr), rem = RTA_PAYLOAD(attr); RTA_OK(i, rem);
	     i = RTA_NEXT(i, rem)) {
		char chstr[32];

		switch (i->rta_type) {
		case IFLA_XDP_XSTATS_SCOPE_SHARED:
			open_json_object("shared");
			ret = xdp_stats_print_one(ctx->fp, i, typestr, NULL);
			close_json_object();
			break;
		case IFLA_XDP_XSTATS_SCOPE_CHANNEL:
			if (!ch)
				open_json_array(PRINT_JSON, "per-channel");

			snprintf(chstr, sizeof(chstr), "%u", ch);
			open_json_object(chstr);

			snprintf(chstr, sizeof(chstr), "channel%u", ch++);
			ret = xdp_stats_print_one(ctx->fp, i, typestr, chstr);

			close_json_object();
			ctx->saved_ch = ch;
			break;
		default:
			fprintf(stderr, "Unknown XDP statistics scope %u\n",
				i->rta_type);
			return -1;
		}

		if (ret)
			return ret;
	}

	return 0;
}

static int xdp_stats_print(struct xdp_stats_ctx *ctx,
			   const struct rtattr *attr)
{
	struct rtattr *i;
	int rem;

	for (i = RTA_DATA(attr), rem = RTA_PAYLOAD(attr); RTA_OK(i, rem);
	     i = RTA_NEXT(i, rem)) {
		__u16 type = i->rta_type;
		int ret;

		if (ctx->flt_type != IFLA_XDP_XSTATS_TYPE_UNSPEC &&
		    type != ctx->flt_type)
			continue;

		switch (type) {
		case IFLA_XDP_XSTATS_TYPE_XDP:
		case IFLA_XDP_XSTATS_TYPE_XSK:
			const char *typestr = xdp_stats_types[type];
			__u32 ifindex = ctx->cur_if;
			bool resume_if;

			if (!typestr)
				goto unknown;

			resume_if = ctx->saved_if == ifindex;
			if (resume_if && ctx->saved_type == type)
				goto resume_type;

			xdp_stats_cleanup_ctx(ctx, !resume_if);
			ctx->saved_if = ifindex;
			ctx->saved_type = type;
			ctx->saved_ch = 0;

			if (!resume_if) {
				const char *ifname = ll_index_to_name(ifindex);

				open_json_object(ifname);

				if (!is_json_context()) {
					color_fprintf(ctx->fp, COLOR_IFNAME,
						      "%s", ifname);
					fprintf(ctx->fp, "/%u:\n", ifindex);
				}
			}

			open_json_object(typestr);
resume_type:
			ret = xdp_stats_print_xdpxsk(ctx, i, typestr);
			break;
		default:
unknown:
			fprintf(stderr, "Unknown XDP statistics type %u\n",
				type);
			return -1;
		}

		if (ret)
			return ret;
	}

	return 0;
}

static int xdp_stats_iter(struct nlmsghdr *n, void *arg)
{
	const struct if_stats_msg *ifsm = NLMSG_DATA(n);
	struct rtattr *tb[__IFLA_STATS_MAX];
	struct xdp_stats_ctx *ctx = arg;
	int len = n->nlmsg_len;

	len -= NLMSG_LENGTH(sizeof(*ifsm));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (ctx->flt_if && ifsm->ifindex != ctx->flt_if)
		return 0;

	parse_rtattr(tb, IFLA_STATS_MAX, IFLA_STATS_RTA(ifsm), len);

	if (!tb[IFLA_STATS_LINK_XDP_XSTATS])
		return 0;

	ctx->cur_if = ifsm->ifindex;
	return xdp_stats_print(ctx, tb[IFLA_STATS_LINK_XDP_XSTATS]);
}

int iplink_xdp_stats(int argc, char **argv)
{
	__u32 filt_mask = IFLA_STATS_FILTER_BIT(IFLA_STATS_LINK_XDP_XSTATS);
	const char *dev = NULL, *type = NULL;
	struct xdp_stats_ctx ctx = {
		.flt_type	= IFLA_XDP_XSTATS_TYPE_UNSPEC,
		.fp		= stdout,
	};
	int i, ret = 0;

	while (argc > 0) {
		if (!matches(*argv, "dev")) {
			NEXT_ARG();

			if (dev)
				duparg2("dev", *argv);

			dev = *argv;
		} else if (!matches(*argv, "type")) {
			NEXT_ARG();

			if (type)
				duparg2("type", *argv);

			type = *argv;
		} else if (!matches(*argv, "help")) {
			fprintf(stderr,
				"Usage: ip link xdpstats [ dev DEV ] [ type TYPE ]\n"
				"   TYPE xdp    filter regular XDP queues\n"
				"   TYPE xsk    filter XSK queues\n");
			return -1;
		} else {
			fprintf(stderr,
				"Command \"%s\" is unknown, try \"ip link xdpstats help\"\n",
				*argv);
			return -1;
		}

		argc--;
		argv++;
	}

	if (!dev)
		goto parse_type;

	ctx.flt_if = ll_name_to_index(dev);
	if (!ctx.flt_if) {
		fprintf(stderr, "Device \"%s\" does not exist\n", dev);
		return -1;
	}

parse_type:
	if (!type)
		goto send_req;

	for (i = IFLA_XDP_XSTATS_TYPE_START;
	     i < __IFLA_XDP_XSTATS_TYPE_CNT;
	     i++)
		if (!strcmp(type, xdp_stats_types[i])) {
			ctx.flt_type = i;
			break;
		}

	if (i == __IFLA_XDP_XSTATS_TYPE_CNT) {
		fprintf(stderr,
			"Type \"%s\" is invalid, try \"ip link xdpstats help\"\n",
			type);
		return -1;
	}

send_req:
	if (rtnl_statsdump_req_filter(&rth, AF_UNSPEC, filt_mask) < 0) {
		perror("Cannont send dump request");
		return -1;
	}

	new_json_obj(json);
	open_json_object(NULL);

	if (rtnl_dump_filter(&rth, xdp_stats_iter, &ctx) < 0) {
		fprintf(stderr, "Dump terminated\n");
		ret = -1;
	}

	xdp_stats_cleanup_ctx(&ctx, true);
	close_json_object();
	delete_json_obj();

	return ret;
}
