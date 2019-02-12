/* $Id: minissdpc.c,v 1.32 2016/10/07 09:04:36 nanard Exp $ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * Project : miniupnp
 * Web : http://miniupnp.free.fr/
 * Author : Thomas BERNARD
 * copyright (c) 2005-2019 Thomas Bernard
 * This software is subjet to the conditions detailed in the
 * provided LICENCE file. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "minissdpc-libuv.h"

#include "codelength.h"
#include <uv.h>

struct userdata_s
{
	void* cb;
	void* userdata;
};

static void connect_cb(uv_connect_t* req, int status)
{
	uv_stream_t *stream = req->handle;
	struct userdata_s *us = stream->data;
	void(*user_connect_cb)(void*, void*) = us->cb;

	if(status < 0)
		user_connect_cb(0, us->userdata);
	else
		user_connect_cb(req->handle, us->userdata);

	free(req);
	free(us);

	if(status < 0)
		free(stream);
}

int
connectToMiniSSDPD(const char * socketpath, void(*user_connect_cb)(void* connect, void* userdata), void *userdata)
{
	if(user_connect_cb == 0)
		return MINISSDPC_INVALID_INPUT;

	if(!socketpath)
		socketpath = "/var/run/minissdpd.sock";

	uv_pipe_t *p = malloc(sizeof(uv_pipe_t));

	if(uv_pipe_init(uv_default_loop(), p, 1) < 0)
		return MINISSDPC_SOCKET_ERROR;

	uv_connect_t *conn = malloc(sizeof(uv_connect_t));
	struct userdata_s *us = malloc(sizeof(struct userdata_s));
	us->cb = user_connect_cb;
	us->userdata = userdata;
	p->data = us;
	uv_pipe_connect(conn, p, socketpath, &connect_cb);
	return MINISSDPC_SUCCESS;
}

static void
close_cb(uv_handle_t *handle)
{
	free(handle);
}

MINIUPNP_LIBSPEC void
disconnectFromMiniSSDPD(void *session)
{
	uv_close((uv_handle_t *)session, close_cb);
}

static void write_cb(uv_write_t* req, int status)
{
	uv_stream_t* stream = req->handle;
	struct userdata_s *us = stream->data;
	void(*user_write_cb)(void*, int, void*) = us->cb;
	user_write_cb(req->handle, status == 0, us->userdata);
	// free(req->bufs->base);
	free(req);
	free(us);
}

MINIUPNP_LIBSPEC int
requestDevicesFromMiniSSDPD(void *session, const char * devtype, void(*requestFinish)(void *connect, int success, void* userdata), void* userdata)
{
	char *buffer;
	char *p;
	unsigned int stsize;

	if (devtype == NULL)
	{
		return MINISSDPC_UNKNOWN_ERROR;
	}
	stsize = strlen(devtype);

	buffer = malloc(256);
	if(buffer == NULL)
	{
		return MINISSDPC_MEMORY_ERROR;
	}
	p = buffer;

	if(stsize == 8 && 0 == memcmp(devtype, "ssdp:all", 8))
	{
		buffer[0] = 3;  /* request type 3 : everything */
	}
	else
	{
		buffer[0] = 1; /* request type 1 : request devices/services by type */
	}

	p++;
	unsigned int l = stsize;
	CODELENGTH(l, p);

	if(p + stsize > buffer + 256)
	{
		/* devtype is too long ! */
		#ifdef DEBUG
		fprintf(stderr, "devtype is too long ! stsize=%u sizeof(buffer)=%u\n",
		        stsize, (unsigned)sizeof(buffer));
		#endif /* DEBUG */
		free(buffer);
		return MINISSDPC_INVALID_INPUT;
	}

	memcpy(p, devtype, stsize);
	p += stsize;
	uv_write_t *req = malloc(sizeof(uv_write_t));

	if(req == NULL)
	{
		free(buffer);
		return MINISSDPC_MEMORY_ERROR;
	}

	struct userdata_s *us = malloc(sizeof(struct userdata_s));

	if(us == NULL)
	{
		free(req);
		free(buffer);
		return MINISSDPC_MEMORY_ERROR;
	}

	us->cb = requestFinish;
	us->userdata = userdata;
	uv_stream_t* stream = session;
	stream->data = us;
	uv_buf_t data[] =
	{
		{ .base = buffer, .len = p - buffer }
	};
	uv_write(req, stream, data, 1, write_cb);
	return MINISSDPC_SUCCESS;
}

static void alloc_cb(uv_handle_t* handle, size_t size, uv_buf_t* buf)
{
	(void)handle;
	buf->base = malloc(size);
	buf->len = size;
}

static void read_cb(uv_stream_t *stream, ssize_t size, const uv_buf_t* buffer)
{
	struct userdata_s *us = stream->data;
	void(*user_write_cb)(void *connect, void *userdata, struct UPNPDev*) = us->cb;
	struct UPNPDev * devlist = NULL;
	char * p = buffer->base;
	unsigned int i, ndev;

	if(size == 0)
	{
		return;
	}

	if(size < 0)
	{
		user_write_cb(stream, us->userdata, devlist);
		uv_read_stop(stream);
		free(us);
		stream->data = NULL;
		return;
	}

	ndev = *p;
	p++;

	for(i = 0; i < ndev; i++)
	{
		unsigned int urlsize;
		char *url = NULL;
		unsigned int stsize;
		char *st = NULL;
		unsigned int usnsize;
		char *usn = NULL;

		DECODELENGTH(urlsize, p);
		if(size != 0)
		{
			url = strndup(p, urlsize);

			if(url == NULL)
				break;
		}
		p += urlsize;

		DECODELENGTH(stsize, p);
		if(size != 0)
		{
			st = strndup(p, stsize);

			if(st == NULL)
			{
				free(url);
				break;
			}
		}
		p += stsize;

		DECODELENGTH(usnsize, p);
		if(size != 0)
		{
			usn = strndup(p, usnsize);

			if(usn == NULL)
			{
				free(url);
				free(st);
				break;
			}
		}
		p += usnsize;

		struct UPNPDev *tmp = (struct UPNPDev *)malloc(sizeof(struct UPNPDev)+urlsize+stsize+usnsize);
		if(tmp == NULL)
		{
			free(url);
			free(st);
			free(usn);
			break;
		}

		tmp->pNext = devlist;
		tmp->descURL = tmp->buffer;
		tmp->st = tmp->buffer + 1 + urlsize;
		tmp->usn = tmp->buffer + 1 + urlsize + 1 + stsize;
		memcpy(tmp->descURL, url, urlsize+1);
		memcpy(tmp->st, st, stsize+1);
		memcpy(tmp->usn, usn, usnsize+1);
		free(url);
		free(st);
		free(usn);
		tmp->scope_id = 0;  /* default value. scope_id is not available with MiniSSDPd */
		devlist = tmp;
	}

	user_write_cb(stream, us->userdata, devlist);
	uv_read_stop(stream);
	stream->data = NULL;
	free(us);
}

void
receiveDevicesFromMiniSSDPD(void *session, void(*requestFinish)(void *session, void *userdata, struct UPNPDev*), void* userdata)
{
	struct userdata_s *us = malloc(sizeof(struct userdata_s));
	us->cb = requestFinish;
	us->userdata = userdata;
	uv_stream_t *stream = session;
	stream->data = us;
	uv_read_start(stream, alloc_cb, read_cb);
}
