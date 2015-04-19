/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR
#define _GNU_SOURCE 

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#include <stdlib.h>
#include "aes-crypt.h"
#include <ctype.h>
#include <limits.h>

       
#endif

char *mountPath;
char fullPath[512];

static void fullpath(const char **path)
{
    strcpy(fullPath, mountPath);
    strncat(fullPath, *path, 512); // ridiculously long paths will
				    // break here
    // log_msg("    bb_fullpath:  rootdir = \"%s\", path = \"%s\", fpath = \"%s\"\n",
	   //  BB_DATA->rootdir, path, fpath);
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	fullpath(&path);

	int res;

	res = lstat(fullPath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	fullpath(&path);
	int res;

	res = access(fullPath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	fullpath(&path);
	int res;

	res = readlink(fullPath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	fullpath(&path);
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	dp = opendir(fullPath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	fullpath(&path);
	int res;

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(fullPath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fullPath, mode);
	else
		res = mknod(fullPath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	fullpath(&path);
	int res;

	res = mkdir(fullPath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	fullpath(&path);
	int res;

	res = unlink(fullPath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	fullpath(&path);
	int res;

	res = rmdir(fullPath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	fullpath(&path);
	int res;

	res = chmod(fullPath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	fullpath(&path);
	int res;

	res = lchown(fullPath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	fullpath(&path);
	int res;

	res = truncate(fullPath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	fullpath(&path);
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fullPath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	fullpath(&path);
	int res;

	res = open(fullPath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	fullpath(&path);
	//int fd;
	int res;
	FILE *fd;
	FILE *f2;
	
	(void) fi;
	fd = fopen(fullPath, "rb+");
	if(!fd)
			return -errno;

	char * membuf;	

 	f2 = open_memstream(&membuf, &size);
 	do_crypt(fd,f2,0,"hello");

	res = fread(buf,1,size,f2);

	if (res == -1)
		res = -errno;

	fclose(fd);
	fclose(f2);
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	fullpath(&path);
	//int fd;
	int res;
	FILE *fd;
	FILE *f2;
	
	(void) fi;
	fd = fopen(fullPath, "wb+");
	if(!fd)
			return -errno;

	char * membuf;	

	//FILE* f = fopen(fullPath, "rb");
 	f2 = open_memstream(&membuf, &size);
	res = fwrite(buf,1,size,f2);

	do_crypt(f2,fd,1,"hello");

    /*open_memstream*/

	//res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	fclose(fd);
	//fclose(f);
	fclose(f2);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	fullpath(&path);
	int res;

	res = statvfs(fullPath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) 
{
	fullpath(&path);
    (void) fi;

    int res;
    res = creat(fullPath, mode);
    if(res == -1)
	return -errno;

    close(res);

    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	fullpath(&path);
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) fullPath;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	fullpath(&path);
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) fullPath;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	fullpath(&path);
	int res = lsetxattr(fullPath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	fullpath(&path);
	int res = lgetxattr(fullPath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	fullpath(&path);
	int res = llistxattr(fullPath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	fullpath(&path);
	int res = lremovexattr(fullPath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create     = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	umask(0);
	char *password = argv[1];
	mountPath = argv[2];
	argv[1] = argv[3];
	argc-=2;

	return fuse_main(argc, argv, &xmp_oper, NULL);
}
