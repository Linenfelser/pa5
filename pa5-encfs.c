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

#define ENCRYPT 1
#define DECRYPT 0
#define PASS -1


char *encryptKey;
char *mountPath;
char fullPath[512];

static void fullpath(const char **path)
{
    strcpy(fullPath, mountPath);
    strncat(fullPath, *path, 512); // coppies the first 512 bytes of *path and cat to end of fullPath
    
    // printf("%s\n","WHAT THE FUCK" );
    // printf("path is: %s\n",path);
    // printf("fullPath is: %s\n", fullPath);
}


#ifdef HAVE_SETXATTR
static int encfs_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	fullpath(&path);
	int res = lsetxattr(fullPath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int encfs_getxattr(const char *path, const char *name, char *value, size_t size)
{
	fullpath(&path);
	int res = lgetxattr(fullPath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encfs_listxattr(const char *path, char *list, size_t size)
{
	fullpath(&path);
	int res = llistxattr(fullPath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encfs_removexattr(const char *path, const char *name)
{
	fullpath(&path);
	int res = lremovexattr(fullPath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static int encfs_getattr(const char *path, struct stat *stbuf)
{
	fullpath(&path);

	int res;

	res = lstat(fullPath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_access(const char *path, int mask)
{
	fullpath(&path);
	int res;

	res = access(fullPath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_readlink(const char *path, char *buf, size_t size)
{
	fullpath(&path);
	int res;

	res = readlink(fullPath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int encfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
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
		//comment out to turn off everything in the folder 
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int encfs_mknod(const char *path, mode_t mode, dev_t rdev)
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

static int encfs_mkdir(const char *path, mode_t mode)
{
	fullpath(&path);
	int res;

	res = mkdir(fullPath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_unlink(const char *path)
{
	fullpath(&path);
	int res;

	res = unlink(fullPath);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_rmdir(const char *path)
{
	fullpath(&path);
	int res;

	res = rmdir(fullPath);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_chmod(const char *path, mode_t mode)
{
	fullpath(&path);
	int res;

	res = chmod(fullPath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_chown(const char *path, uid_t uid, gid_t gid)
{
	fullpath(&path);
	int res;

	res = lchown(fullPath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_truncate(const char *path, off_t size)
{
	fullpath(&path);
	int res;

	res = truncate(fullPath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_utimens(const char *path, const struct timespec ts[2])
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

static int encfs_open(const char *path, struct fuse_file_info *fi)
{
	fullpath(&path);
	int res;

	res = open(fullPath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int encfs_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	fullpath(&path);
	//int fd;
	int res;
	FILE *fd;
	FILE *f2;
	char *membuf;
	char attr_value[8];
	int operation = PASS;
	ssize_t attr_length; 
	(void) fi;
	(void) offset;

	fd = fopen(fullPath, "rb+");
	if(!fd)
			return -errno;

 	f2 = open_memstream(&membuf, &size);
 	attr_length = encfs_getxattr(path, "user.pa5-encfs.encrypted", attr_value, 4);

 	//error checking
 	// if((f2 == NULL) || (fd == NULL))
 	// {
 	// 	fprintf(stderr, "%s\n", "error with open_memstream or fopen in read" );
 	// 	return -errno;
 	// }

 	//if attr_length != -1

 	if(attr_length > 3)
 	{
 		operation = DECRYPT; //0 = decrypt
 	}
 	//else means that the file is not encrypted and the operation should be -1 (do nothing) 

 	do_crypt(fd,f2,operation,encryptKey);

	res = fread(buf,1,size,f2);

	if (res == -1)
		res = -errno;

	fclose(fd);
	fclose(f2);
	return res;
}

static int encfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	fullpath(&path);
	int operation = PASS;
	int res;
	FILE *fd; //o_stream
	FILE *f2; //i_stream
	char attr_value[8];
	char *membuf;
	ssize_t attr_length;
	//ssize_t *memsize; //replace this pointer with size below and then give memsize to fread 

	(void) fi;
	(void) offset;


	fd = fopen(fullPath, "wb+");
	if(!fd)
			return -errno;

	//FILE* f = fopen(fullPath, "rb");
 	f2 = open_memstream(&membuf, &size);
 	attr_length = encfs_getxattr(path, "user.pa5-encfs.encrypted", attr_value, 4); //check xattr to see if already encrypted

 	//error checking
 	if((f2 == NULL) || (fd == NULL))
 	{
 		fprintf(stderr, "%s\n", "error with open_memstream or fopen in write" );
 		return -errno;
 	}


 	if(attr_length != -1)
 	//if(attr_length > 3) //if there is an attribute value
 	{
 		operation = ENCRYPT; //1 is for encrypt 
 	}
 	//else means that the file is not encrypted and the operation should be -1 (do nothing) 

	res = fwrite(buf,1,size,f2);

	do_crypt(f2,fd,operation,encryptKey);

    /*open_memstream*/

	//res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	fclose(fd);
	//fclose(f);
	fclose(f2);

	return res;
}

static int encfs_statfs(const char *path, struct statvfs *stbuf)
{
	fullpath(&path);
	int res;

	res = statvfs(fullPath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) 
{
	fullpath(&path);
    (void) fi;

    int res;
    res = creat(fullPath, mode);
    if(res == -1)
	return -errno;

	res = lsetxattr(fullPath, "user.pa5-encfs.encrypted", "true", strlen("true"), XATTR_CREATE);

    close(res);

    return 0;
}


static int encfs_release(const char *path, struct fuse_file_info *fi)
{
	fullpath(&path);
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) fullPath;
	(void) fi;
	return 0;
}

static int encfs_fsync(const char *path, int isdatasync,
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


static struct fuse_operations encfs_oper = {
	.getattr	= encfs_getattr,
	.access		= encfs_access,
	.readlink	= encfs_readlink,
	.readdir	= encfs_readdir,
	.mknod		= encfs_mknod,
	.mkdir		= encfs_mkdir,
	.symlink	= encfs_symlink,
	.unlink		= encfs_unlink,
	.rmdir		= encfs_rmdir,
	.rename		= encfs_rename,
	.link		= encfs_link,
	.chmod		= encfs_chmod,
	.chown		= encfs_chown,
	.truncate	= encfs_truncate,
	.utimens	= encfs_utimens,
	.open		= encfs_open,
	.read		= encfs_read,
	.write		= encfs_write,
	.statfs		= encfs_statfs,
	.create     = encfs_create,
	.release	= encfs_release,
	.fsync		= encfs_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= encfs_setxattr,
	.getxattr	= encfs_getxattr,
	.listxattr	= encfs_listxattr,
	.removexattr	= encfs_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	umask(0);

	if(argc < 4)
	{
		fprintf(stderr, "%s\n", "missing argument, format like: <encription key> <directory to mirror> <directory to mount to>");
		return 1;
	}
	encryptKey = argv[1];
	mountPath = argv[2];
	argv[1] = argv[3]; //need to format the argumets back to what fuse_main is expecting
	argc-=2;

	return fuse_main(argc, argv, &encfs_oper, NULL);
}










