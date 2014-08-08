#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <string.h>
#include <time.h>
#include "cryptodev.h"

#define DATA_SIZE       4096
#define BLOCK_SIZE      16
#define KEY_SIZE        24 /*192 bit*/

struct data_op{
	char src[DATA_SIZE];	/*sroucr data/input data*/
	char dst[DATA_SIZE];	/*dest data/output data*/
	char iv[BLOCK_SIZE];	/*init vector*/
	char key[KEY_SIZE];		/*key*/
} ;

/*decrypto*/
static int decrypto(int cfd)
{
	struct session_op sess;
	struct crypt_op cryp;
	struct data_op data;
	
	int r_fd, w_fd,i;
	int ret_r, ret_w;
	int count = 0;

	char *src_file = "/mnt/usbhost0/tar.tar.bak";
	char *dst_file = "/mnt/usbhost0/tar1.tar";

	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));
	memset(&data, 0, sizeof(data));

	for(i = 0;i < KEY_SIZE;i++){
		data.key[i] = 0x01;
	}

	/*open source file*/
	r_fd = open(src_file,O_RDWR,0);
	if(r_fd < 0) {
		perror("open(src_fild)");
		return -1;
	}
	printf("open src_file success :%s\n",src_file);
	/*creat dst file*/
	w_fd = open(dst_file,O_RDWR|O_CREAT|O_TRUNC,0777);
	if(w_fd < 0){
		perror("open(dst_file)");
		close(r_fd);
		return -1;
	}
	printf("creat dst_file success :%s\n",dst_file);
	/* Get crypto session for AES128 */
	sess.cipher = CRYPTO_AES_CBC;			/*alg type select*/
	sess.keylen = KEY_SIZE;					/*secret key size*/
	sess.key = data.key;					/*key*/
	if (ioctl(cfd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return -1;
	}

	/* Encrypt data.in to data.encrypted */
	while(1) {

		ret_r = read(r_fd,data.src,DATA_SIZE);
		if(ret_r < 0) {
			perror("read(r_fd)");
			close(r_fd);
			close(w_fd);
			return -1;
		}
		cryp.ses = sess.ses;					/*session identifier*/
		cryp.len = sizeof(data.src);				/*encrypto data size*/
		cryp.src = data.src;						/*source data*/
		cryp.dst = data.dst;				/*output data*/
		cryp.iv = data.iv;						/*IV number*/
		cryp.op = COP_DECRYPT;					/*encrypto or decrypto*/
		if (ioctl(cfd, CIOCCRYPT, &cryp)) {
			perror("ioctl(CIOCCRYPT)");
			close(r_fd);
			close(w_fd);
			return -1;
		}

		if(ret_r < DATA_SIZE){
			ret_w = write(w_fd,data.dst,ret_r);
			if(ret_w < 0) {
				perror("write(w_fd)");
				close(r_fd);
				close(w_fd);
				return -1;
			}
			break;
		}
		ret_w = write(w_fd,data.dst,DATA_SIZE);
		if(ret_w < 0) {
			perror("write(w_fd)");
			close(r_fd);
			close(w_fd);
			return -1;
		}
		printf("count ---> %d\n",count++);
	}
	if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
		return -1;
	}
	close(r_fd);
	close(w_fd);

	return 0;
}

/*encrypto*/
static int encrypto(int cfd)
{
	struct session_op sess;
	struct crypt_op cryp;
	struct data_op data;
	
	int r_fd, w_fd,i;
	int ret_r, ret_w;
	int count = 0;

	char *src_file = "/mnt/usbhost0/tar.tar";
	char *dst_file = "/mnt/usbhost0/tar.tar.bak";

	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));
	memset(&data, 0, sizeof(data));

	for(i = 0;i < KEY_SIZE;i++){
		data.key[i] = 0x01;
	}

	/*open source file*/
	r_fd = open(src_file,O_RDWR,0);
	if(r_fd < 0) {
		perror("open(src_fild)");
		return -1;
	}
	printf("open src_file success :%s\n",src_file);
	/*creat dst file*/
	w_fd = open(dst_file,O_RDWR|O_CREAT|O_TRUNC,0777);
	if(w_fd < 0){
		perror("open(dst_file)");
		close(r_fd);
		return -1;
	}
	printf("creat dst_file success :%s\n",dst_file);
	/* Get crypto session for AES128 */
	sess.cipher = CRYPTO_AES_CBC;			/*alg type select*/
	sess.keylen = KEY_SIZE;					/*secret key size*/
	sess.key = data.key;					/*key*/
	if (ioctl(cfd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return -1;
	}

	/* Encrypt data.in to data.encrypted */
	while(1) {

		ret_r = read(r_fd,data.src,DATA_SIZE);
		if(ret_r < 0) {
			perror("read(r_fd)");
			close(r_fd);
			close(w_fd);
			return -1;
		}
		cryp.ses = sess.ses;					/*session identifier*/
		cryp.len = sizeof(data.src);				/*encrypto data size*/
		cryp.src = data.src;						/*source data*/
		cryp.dst = data.dst;				/*output data*/
		cryp.iv = data.iv;						/*IV number*/
		cryp.op = COP_ENCRYPT;					/*encrypto or decrypto*/
		if (ioctl(cfd, CIOCCRYPT, &cryp)) {
			perror("ioctl(CIOCCRYPT)");
			close(r_fd);
			close(w_fd);
			return -1;
		}

		if(ret_r < DATA_SIZE){
			ret_w = write(w_fd,data.dst,ret_r);
			if(ret_w < 0) {
				perror("write(w_fd)");
				close(r_fd);
				close(w_fd);
				return -1;
			}
			break;
		}
		ret_w = write(w_fd,data.dst,DATA_SIZE);
		if(ret_w < 0) {
			perror("write(w_fd)");
			close(r_fd);
			close(w_fd);
			return -1;
		}
		printf("count ---> %d\n",count++);
	}
	/* Finish crypto session */
	if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
		return -1;
	}
	close(r_fd);
	close(w_fd);

	return 0;
}


int main(int argc,char **argv)
{
	int fd = -1, cfd = -1;
	time_t start, end;

	/* Open the crypto device */
	fd = open("/dev/crypto", O_RDWR, 0);
	if (fd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	/* Clone file descriptor */
	if (ioctl(fd, CRIOGET, &cfd)) {
		perror("ioctl(CRIOGET)");
		return -1;
	}

	/* Set close-on-exec (not really neede here */
	if (fcntl(cfd, F_SETFD, 1) == -1) {
		perror("fcntl(F_SETFD)");
		return -1;
	}
#if 0	
	start = time(NULL);
	/* encrypto data */
	if (encrypto(cfd))
		return -1;
	end = time(NULL);
	printf("enrypto over !\n");
#endif

#if 1
	start = time(NULL);
	if(decrypto(cfd))
		return -1;
	end = time(NULL);
	printf("enrypto over !\n");
#endif
	printf("waset of time second %d\n",end-start);
	/* Close cloned descriptor */
	if (close(cfd)) {
		perror("close(cfd)");
		return -1;
	}

	/* Close the original descriptor */
	if (close(fd)) {
		perror("close(fd)");
		return -1;
	}

	return 0;
}
