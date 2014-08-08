#include <linux/if_alg.h>
#include <sys/types.h>    
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>




/*

struct msghdr {

	void            *msg_name;

	int             msg_namelen;

	struct iovec    *msg_iov;

	__kernel_size_t msg_iovlen;

	void            *msg_control;

	__kernel_size_t msg_controllen;

	unsigned        msg_flags;

};

struct iovec{

	void __user     *iov_base;

	__kernel_size_t iov_len;

};


struct cmsghdr {
	socklen_t cmsg_len;
	int       cmsg_level;
	int       cmsg_type;

};


*/

struct sockaddr_alg sa = {
	.salg_family = AF_ALG,
	.salg_type = "abskcipher",
	.salg_name = "cbc(aes)"
};

struct msghdr msg = {};
struct cmsghdr *cmsg;
struct af_alg_iv *iv;
struct iovec iov;
struct af_alg_control *con;
int i;


int main(int argv,char **argv)
{
	char cbuf[MSG_SPACE(4) + CMSG_SPACE(20)];
	char buf[167];
	int ret_socket, ret_accept;
/*socket AF_ALG*/
	ret_socket = socket(AF_ALG,SOCK_SEQPACKET,0);
/*bind*/
	bind(ret_socket,(struct sockaddr*)&sa,sizeof(sa));
/*set key*/
	setsockopt(ret_socket,SOL_ALG,ALG_SET_KEY,"\x06\xa9\x21\x40\x36\xb8\xa1\x5b",16);

	ret_accept = accept(ret_socket,NULL,0);

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32*)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;

	cmsg = CMSG_NXTHDR(&msg,cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(20);
	/*sent cmsg value to iv*/
	iv = (void*)CMSG_DATA(cmsg);
	iv->ivlen = 16;

	memcpy(iv->iv, "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30", "\xb4\x22\xda\x80\x2c\x9f\xac\x41", 16);

	iov.iov_base = "Single block msg";
	iov.iov_len = 16;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	sendmsg(ret_accept, &msg, co);
	read(ret_accept, buf, 16);

	for (i = 0; i < 16; i++) {
		printf("%02x", (unsigned char)buf[i]);
	}
	printf("\n");

	close(opfd);
	close(tfmfd);


	return 0;
}
