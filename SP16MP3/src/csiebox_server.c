#include "csiebox_server.h"
#include "csiebox_common.h"
#include "connect.h"
#include "hash.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <dirent.h>
#define filemaxno 150
static int parse_arg(csiebox_server* server, int argc, char** argv);
static int handle_request(csiebox_server* server, int conn_fd);
static int get_account_info(
  csiebox_server* server,  const char* user, csiebox_account_info* info);
static void login(
  csiebox_server* server, int conn_fd, csiebox_protocol_login* login);
static void logout(csiebox_server* server, int conn_fd);
static char* get_user_homedir(
  csiebox_server* server, csiebox_client_info* info);
static int sync_meta_and_file(csiebox_server *server, int conn_fd, csiebox_protocol_meta *meta);
static int sync_hardlink(csiebox_server *server, int conn_fd, csiebox_protocol_hardlink *hardlink);
static int sync_rm(csiebox_server *server, int conn_fd, csiebox_protocol_rm *rm);
static void traversalsdir(csiebox_server *server, int conn_fd, const char *dir_name, hash *hash_ptr_forhdlink);
int init_hash_forhdlink(hash* h, int n);
int put_into_hash_forhdlink(hash* h, void* contain, int hash_code);
int get_from_hash_forhdlink(hash* h, void** contain, int hash_code, char *path);
int del_from_hash_forhdlink(hash* h, int hash_code, char *path);
void clean_hash_forhdlink(hash* h);
void destroy_hash_forhdlink(hash* h);
int traversal_hash_forhdlink(hash *h, char *path);
static int sync_meta_assign2(csiebox_server *server, int conn_fd, char *path);
static int sync_file_assign2(csiebox_server *server, int conn_fd, char *path);
static int sync_hdlink_assign2(csiebox_server *server, int conn_fd, char *path, char *otherpath);
#define DIR_S_FLAG (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)//permission you can use to create new file
#define REG_S_FLAG (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)//permission you can use to create new directory
#define BUFFSIZE 4096
//assignment 2
int init_hash_forhdlink(hash* h, int n) {
  if (n <= 0 || h->node != NULL) {
    return 0;
  }
  h->node = (hash_node**)malloc(sizeof(hash_node*) * n);
  if (h->node == NULL) {
    return 0;
  }
  memset(h->node, 0, sizeof(hash_node*) * n);
  h->n = n;
  return 1;
}

int put_into_hash_forhdlink(hash* h, void* contain, int hash_code) {
	fprintf(stderr, "welcome put_into_hash_forhdlink\n");
	
  int pos = hash_code % h->n;
  if (pos < 0) {
    pos = h->n + pos;
  }
  hash_node* n = h->node[pos];
  if (n == NULL) {
    hash_node* new_node = (hash_node*)malloc(sizeof(hash_node));
    if (new_node == NULL) {
      fprintf(stderr, "malloc fail\n");
    }
    new_node->contain = contain;
    new_node->hash_code = hash_code;
    new_node->next = NULL;
    h->node[pos] = new_node;
	fprintf(stderr, "return value\n");
    return 0;
  }
  int same = 0;
  for (; n->next != NULL; n = n->next) {
	//fprintf(stderr, "for loop is not break\n");
    if (n->hash_code == hash_code) {
      //printf("n->hash_code = %d, hash_code = %d\n", n->hash_code, hash_code);
      same = 1;
    }
  }
	//fprintf(stderr, "for loop is over\n");
  if (n->hash_code == hash_code) {
    same = 1;
  }
  hash_node* new_node = (hash_node*)malloc(sizeof(hash_node));
  if (new_node == NULL) {
    fprintf(stderr, "malloc fail\n");
  }
  new_node->contain = contain;
  new_node->hash_code = hash_code;
  new_node->next = NULL;
  n->next = new_node;
  if(same){
	fprintf(stderr, "return value\n");
    return 1;
  }
  else{
	fprintf(stderr, "return value\n");
    return 0;
  }
}

int get_from_hash_forhdlink(hash* h, void** contain, int hash_code, char *path) {
  *contain = NULL;
  int pos = hash_code % h->n;
  if (pos < 0) {
    pos = h->n + pos;
  }
  hash_node* n = h->node[pos];
  if (n == NULL) {
    printf("n == NULL\n");
    return 0;
  }
  for (; n != NULL; n = n->next) {
    if (n->hash_code == hash_code && strcmp((char *)n->contain, path) != 0) {
      *contain = n->contain;
      return 1;
    }
  }
  printf("not in hardlink hash\n");
  return 0;
}

int del_from_hash_forhdlink(hash* h, int hash_code, char *path) {
  //*contain = NULL;
  int pos = hash_code % h->n;
  if (pos < 0) {
    pos = h->n + pos;
  }
  hash_node* n = h->node[pos];
  if (n == NULL) {
    return 0;
  }
  hash_node* pre = NULL;
  for (; n != NULL; n = n->next) {
    if (n->hash_code == hash_code && !strcmp((char *)n->contain, path)) {
      if (pre != NULL) {
        pre->next = n->next;
      } else {
        h->node[pos] = NULL;
      }
      //*contain = n->contain;
      free(n);
      return 1;
    }
    pre = n;
  }
  return 0;
}

void clean_hash_forhdlink(hash* h) {
  int i = 0;
  for (i = 0; i < h->n; ++i) {
    hash_node* n = h->node[i];
    while (n != NULL) {
      hash_node* next = n->next;
      free(n);
      n = next;
    }
  }
  free(h->node);
  h->node = NULL;
  h->n = 0;
}

void destroy_hash_forhdlink(hash* h) {
  int i = 0;
  for (i = 0; i < h->n; ++i) {
    hash_node* n = h->node[i];
    while (n != NULL) {
      hash_node* next = n->next;
      free(n->contain);
      free(n);
      n = next;
    }
  }
  free(h->node);
  h->node = NULL;
  h->n = 0;
}
//traversal hashmap when sync rm, and then return the hashcode, so can call del_from_hashforhdlink by the hashcode
int traversal_hash_forhdlink(hash *h, char *path){
	int i = 0;
	for(i = 0; i < h->n; i++){
		hash_node *tmp = h->node[i];
		while(tmp != NULL){
			if(!strcmp((char*)tmp->contain, path)){
				return tmp->hash_code;
			}
			tmp = tmp->next;
		}
	}
	return -1;
}
//sync_meta_assign2
static int sync_meta_assign2(csiebox_server *server, int conn_fd, char *path){
	fprintf(stderr, "come to meta\n");
	fprintf(stderr, "path is %s\n", path);
	csiebox_protocol_meta req;
	char clientpath[PATH_MAX];
	memset(clientpath, 0, sizeof(clientpath));
	char pathtmp[PATH_MAX];
	memset(pathtmp, 0, sizeof(pathtmp));
	strcpy(pathtmp, server->arg.path);
	strcat(pathtmp, "/");
	strcat(pathtmp, server->client[conn_fd]->account.user);
	int len = strlen(pathtmp);
	strcat(clientpath, path+len);
	memset(&req, 0, sizeof(csiebox_protocol_meta));
	req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	req.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
	req.message.body.pathlen = strlen(clientpath);   //not sure pathlen == strlen(path) ? by own decision
	if(lstat(path, &(req.message.body.stat)) == -1){
		fprintf(stderr, "lstat fail\n");
	}
	//assign md5 hash value
	if(S_ISREG(req.message.body.stat.st_mode)){
		md5_file(path, req.message.body.hash);
	}
	if(S_ISLNK(req.message.body.stat.st_mode)){
		char buf[PATH_MAX];
		int len;
		memset(buf, 0, PATH_MAX);
		len = readlink(path, buf, PATH_MAX);
		md5(buf, len, req.message.body.hash);
	}
	//send meta req to server
	if(!send_message(conn_fd, &req, sizeof(req))){   //first send meta to client
		fprintf(stderr, "send req fail\n");
		return 0;
	}
	else{
		fprintf(stderr, "send req successful\n");
	}
	//send file path to server
	if(!send_message(conn_fd, clientpath, strlen(clientpath))){    //second send path to client
		fprintf(stderr, "send data fail\n");
		return 0;
	}
	else{
		fprintf(stderr, "send data successful\n");
	}
	//receive the message
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	if(recv_message(conn_fd, &header, sizeof(header))){  //third recvc header from client
		if(header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES && header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_META){
			if(header.res.status == CSIEBOX_PROTOCOL_STATUS_MORE){
				printf("need to sync file\n");
				return 1;
			}
			else if(header.res.status == CSIEBOX_PROTOCOL_STATUS_OK){
				printf("no need to sync file because the file has existed in server\n");
				return 0;
			}
			//fprintf(stderr, "receive from server: %04\n", header.res.status);
			//return (int) header.res.status;
		}
		else{
			fprintf(stderr, "receive from server error\n");
			return 0;
		}
	}
	else{
		fprintf(stderr, "receive from server fail\n");
		return 0;
	}
}
//sync file assign2
static int sync_file_assign2(csiebox_server *server, int conn_fd, char *path){
	csiebox_protocol_file file;
	memset(&file, 0, sizeof(csiebox_protocol_file));
	file.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	file.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
	file.message.header.req.datalen = sizeof(file) - sizeof(file.message.header);
	struct stat sb;
	if(lstat(path, &sb) == -1){
		fprintf(stderr, "lstat fail\n");
	}
	if(S_ISREG(sb.st_mode)){
		FILE *fptr = fopen(path, "rb");
		fseek(fptr, 0, SEEK_END);
		file.message.body.datalen = (uint64_t)ftell(fptr);
		if(!send_message(conn_fd, &file, sizeof(file))){  //fourth send file protocol to client
			fprintf(stderr, "send data fail\n");
		}
		fseek(fptr, 0, SEEK_SET);
		char *buf = (char *)malloc(file.message.body.datalen);
		memset(buf, 0, sizeof(buf));
		size_t n;
		if((n = fread(buf, sizeof(char), file.message.body.datalen, fptr)) < 0){
			fprintf(stderr, "fread data pointed by fptr fail, n = %zd\n", n);
		}
		if(!send_message(conn_fd, buf, file.message.body.datalen)){   //fifth send file's data to client
			fprintf(stderr, "send_message fail\n");
		}
		free(buf);
		fclose(fptr);
		return 1;		
	}
	else if(S_ISLNK(sb.st_mode)){
		char buf[PATH_MAX];
		memset(buf, 0, sizeof(buf));
		readlink(path, buf, PATH_MAX);
		file.message.body.datalen = strlen(buf);
		if(!send_message(conn_fd, &file, sizeof(file))){    //fourth send file protocol to client
			fprintf(stderr, "send data fail\n");
		}
		if(!send_message(conn_fd, buf, file.message.body.datalen)){    //fifth send file's data to client
			fprintf(stderr, "send readlink fail\n");
		}
		fprintf(stderr, "sync symbolic link successful\n");
		return 1;
	}
}
//sync hardlink assign2
static int sync_hdlink_assign2(csiebox_server *server, int conn_fd, char *path, char *otherpath){  //path is the update path of hardlink, and oterpath is the existing path
	fprintf(stderr, "come to hardlink\n");
	fprintf(stderr, "path is %s\n", path);
	csiebox_protocol_hardlink hardlink;  
	char clientpath[PATH_MAX];     //clientpath correspond the existing path, so strcat a "reg's path"
	memset(clientpath, 0, sizeof(clientpath));
	char clienthardlinkpath[PATH_MAX];    //clienthardlinkpath correspond the update path of hardlink, so strcat a "path"
	memset(clienthardlinkpath, 0, sizeof(clienthardlinkpath));
	char pathtmp[PATH_MAX];
	memset(pathtmp, 0, sizeof(pathtmp));
	strcpy(pathtmp, server->arg.path);
	strcat(pathtmp, "/");  
	strcat(pathtmp, server->client[conn_fd]->account.user);
	int len = strlen(pathtmp);
	//strcat(serverpath, client->arg.name);
	//strcat(serverpath, "/");
	//strcat(serverhardlinkpath, "user/");
	//strcat(serverhardlinkpath, client->arg.name);
	//strcat(serverhardlinkpath, "/");
	strcat(clienthardlinkpath, path+len);    //serverhardlink correspond with path(other hardlink's path)
	strcat(clientpath, otherpath+len);   //serverpath correspond with otherpath(exisintg file's path)
	hardlink.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	hardlink.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK;
	hardlink.message.header.req.datalen = sizeof(hardlink) - sizeof(hardlink.message.header);
	hardlink.message.body.srclen = strlen(clienthardlinkpath);   //srclen represent the length of the path of hardlink in the client
	hardlink.message.body.targetlen = strlen(clientpath);    //targetlen represent the length of the existing path in the client
	//send hardlink req to server
	if(!send_message(conn_fd, &hardlink, sizeof(hardlink))){     //first send hardlink protocol to client
		fprintf(stderr, "send req fail\n");
	}
	//send target file path(existing path) to server
	if(!send_message(conn_fd, clientpath, strlen(clientpath))){   //second send clientpath(regfile's path == existing file's path)
		fprintf(stderr, "send serverpath fail\n");
	}
	//send hardlink path to the server
	if(!send_message(conn_fd, clienthardlinkpath, strlen(clienthardlinkpath))){    //third send clienthardlinkpath(update path for hardlink)
		fprintf(stderr, "send serverhardlink fail\n");
	}
	//receive if it's successful
	csiebox_protocol_header header;
	memset( &header, 0, sizeof(header) );
	if( recv_message(conn_fd, &header, sizeof(header) ) ) {   //fourth recv over header from client
		if(header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES && header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK) {
			if(header.res.status == CSIEBOX_PROTOCOL_STATUS_OK){
				printf("sync hardlink for server is successful\n");
				return 1;
			}
			else{
				return 0;
			}
		}
		else{
			return 0;
		}
	}
	else{
		return 0;
	}
}

//traversal sdir
static void traversalsdir(csiebox_server *server, int conn_fd, const char *dir_name, hash *hash_ptr_forhdlink){
	DIR *d;
	/* Open the directory specified by "dir_name". */
	fprintf(stderr, "dir_name is %s\n", dir_name);
	fprintf(stderr, "before open dir\n");
	d = opendir(dir_name);
	fprintf(stderr, "after open dir\n");
	/* Check it was opened. */
	if (!d){
		fprintf(stderr, "Cannot open directory '%s': %s\n", dir_name, strerror(errno));
		exit(EXIT_FAILURE);
	}
	while (1) {
        	struct dirent * entry;
        	//const char * d_name;

        	/* "Readdir" gets subsequent entries from "d". */
		fprintf(stderr, "before read dir\n");
        	entry = readdir(d);
		fprintf(stderr, "after read dir\n");
        	if (!entry) {
            	/* There are no more entries in this directory, so break
               	out of the while loop. */
            		break;
        	}
        	//d_name = entry->d_name;
        	/* Print the name of the file and directory. */
		if (strcmp (entry->d_name, "..") != 0 && strcmp (entry->d_name, ".") != 0) {
			int path_length;
			char *path;
			path = (char*)malloc(PATH_MAX);
			memset(path, 0, sizeof(path));
			path_length = snprintf(path, PATH_MAX, "%s/%s", dir_name, entry->d_name);
			fprintf(stderr, "path is %s\n", path);
			if (path_length >= PATH_MAX) {
				fprintf (stderr, "Path length has got too long.\n");
				exit (EXIT_FAILURE);
			}
			struct stat sb;
			if(lstat(path, &sb) == -1){
				fprintf(stderr, "lstat fail\n");
			}
			if(S_ISREG(sb.st_mode)){
				char otherpath[PATH_MAX];
				fprintf(stderr, "put_into_hash_forhdlink before\n");
				if(put_into_hash_forhdlink(hash_ptr_forhdlink, (void*)path, sb.st_ino) == 1){
					fprintf(stderr, "put_into_hash_forhdlink after\n");
					fprintf(stderr, "get_from_hash_forhdlink before\n");
					if(get_from_hash_forhdlink(hash_ptr_forhdlink, (void**)&otherpath, sb.st_ino, path) == 0){   //path for other hardlink path, otherpath for existing regfile's path
						fprintf(stderr, "get_from_hash_forhdlink fail\n");
					}
					fprintf(stderr, "get_from_hash_forhdlink after\n");
					fprintf(stderr, "sync_hdlink_assign2 before\n");
					if(sync_hdlink_assign2(server, conn_fd, path, otherpath) == 1){  //otherpath is existing reg's path; path is other hardlink path
						printf("sync hardlink is successful\n");
					}
					fprintf(stderr, "sync_hdlink_assign2 after\n");
				}
				else{
					fprintf(stderr, "put_into_hash_forhdlink after\n");
					fprintf(stderr, "sync_meta_assign2 before\n");
					if(sync_meta_assign2(server, conn_fd, path) == 1){
						fprintf(stderr, "sync_meta_assign2 after\n");
						if(sync_file_assign2(server, conn_fd, path) == 1){
							fprintf(stderr, "sync_file_assign2 before\n");
							printf("sync meta and file is successful\n");
						}
					}
					fprintf(stderr, "sync_meta_and_file_assign2 before\n");
				}
				fprintf(stderr, "S_ISREG(sb.st_mode) is over\n");
			}
			else if(S_ISDIR(sb.st_mode)){
				if(sync_meta_assign2(server, conn_fd, path) == 1){
					printf("sync meta and file is successful\n");
				}
				traversalsdir(server, conn_fd, path, hash_ptr_forhdlink);
			}
			else if(S_ISLNK(sb.st_mode)){
				if(sync_meta_assign2(server, conn_fd, path) == 1){
					if(sync_file_assign2(server, conn_fd, path) == 1){
						printf("sync meta and file is successful\n");
					}
				}
			}
		}
	}
	/* After going through all the entries, close the directory. */
	if(closedir (d)){
		fprintf (stderr, "Could not close '%s': %s\n", dir_name, strerror (errno));
		exit (EXIT_FAILURE);
	}
	return;
}

//assignment1
//sync meta
static int sync_meta_and_file(csiebox_server *server, int conn_fd, csiebox_protocol_meta *meta){
	char path[PATH_MAX];
	memset(path, 0, sizeof(path));
	strcpy(path, server->arg.path);
	strcat(path, "/");
	strcat(path, server->client[conn_fd]->account.user);
	char pathtmp[PATH_MAX];
	memset(pathtmp, 0, sizeof(pathtmp));
	if(!recv_message(conn_fd, pathtmp, meta->message.body.pathlen)){
		fprintf(stderr, "recv_message's path fail\n");
	}
	strcat(path, pathtmp);
	fprintf(stderr, "path is %s\n", path);
	csiebox_protocol_meta res;
	memset(&res, 0, sizeof(csiebox_protocol_meta));
	res.message.header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	res.message.header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	res.message.header.res.datalen = sizeof(res) - sizeof(res.message.header);
	csiebox_protocol_header header;
	int st_t;
	st_t = lstat(path, &(res.message.body.stat));
	if(st_t == -1){  //maybe no file since the sdir is empty first
		fprintf(stderr, "lstat fail\n");
		if(S_ISDIR(meta->message.body.stat.st_mode)){
			//fprintf(stderr, "path is %s\n", path);
			mkdir(path, meta->message.body.stat.st_mode);
			/*struct timespec times[2];
			int fd;
			if((fd = open(path, O_RDWR)) < 0){
				fprintf(stderr, "open error\n");
			}
			times[0] = meta->message.body.stat.st_atim;
			times[1] = meta->message.body.stat.st_mtim;
			if(futimens(fd, times) < 0){
				fprintf(stderr, "sync mtime fail\n");
			}
			close(fd);
			if(chmod(path, meta->message.body.stat.st_mode) < 0){
				fprintf(stderr, "sync permission fail\n");
			}*/
			res.message.header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
			header = res.message.header;
			if(!send_message(conn_fd, &header, sizeof(header))){
				fprintf(stderr, "send_message fail\n");
				return 0;
			}
			return 1;
		}
		if(S_ISREG(meta->message.body.stat.st_mode)){
			//fprintf(stderr, "path is %s\n", path);
			fprintf(stderr, "create a new regular file\n");
			res.message.header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
			header = res.message.header;
			if(!send_message(conn_fd, &header, sizeof(header))){  //send the final meta result back to client
				fprintf(stderr, "send_message fail\n");
			}
			csiebox_protocol_file file;
			memset(&file, 0, sizeof(csiebox_protocol_file));
			if(!recv_message(conn_fd, &file, sizeof(file))){  //recv the protocol file from client
				fprintf(stderr, "recv_message file fail, wrong!!\n");
			}
			FILE *fptr = fopen(path, "wb");
			char *buf = (char *)malloc(file.message.body.datalen);
			memset(buf, 0, sizeof(buf));
			if(!recv_message(conn_fd, buf, file.message.body.datalen)){  //recv the data of file from client
				fprintf(stderr, "recv_message fail\n");
			}
			size_t n;
			if((n = fwrite(buf, sizeof(char), file.message.body.datalen, fptr)) <= 0){  //write the data into the file in server
				fprintf(stderr, "fwrite the data into the file fail\n");
			}
			free(buf);
			fclose(fptr);
			struct timespec times[2];
			int fd;
			if((fd = open(path, O_RDONLY)) < 0){
				fprintf(stderr, "open error\n");
			}
			times[0] = meta->message.body.stat.st_atim;
			times[1] = meta->message.body.stat.st_mtim;
			if(futimens(fd, times) < 0){    //sync mtime
				fprintf(stderr, "sync mtime fail\n");
			}
			close(fd);
			if(chmod(path, meta->message.body.stat.st_mode) < 0){    //sync permission
				fprintf(stderr, "sync permission fail\n");
			}
			return 1;
		}
		if(S_ISLNK(meta->message.body.stat.st_mode)){
			//fprintf(stderr, "path is %s\n", path);
			res.message.header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
			header = res.message.header;
			if(!send_message(conn_fd, &header, sizeof(header))){   //send the final meta result back to client
				fprintf(stderr, "send_message fail\n");
			}
			csiebox_protocol_file file;
			memset(&file, 0, sizeof(csiebox_protocol_file));
			if(!recv_message(conn_fd, &file, sizeof(file))){  //recv the protocol file from client
				fprintf(stderr, "recv_message fail\n");
			}
			char *buf = (char *)malloc(file.message.body.datalen);
			memset(buf, 0, sizeof(buf));
			if(!recv_message(conn_fd, buf, file.message.body.datalen)){  //recv the symlink content from the client
				fprintf(stderr, "recv_message fail\n");
			}
			symlink(buf, path);
			struct timespec times[2];
			int fd;
			if((fd = open(path, O_RDONLY)) < 0){
				fprintf(stderr, "open error\n");
			}
			times[0] = meta->message.body.stat.st_atim;
			times[1] = meta->message.body.stat.st_mtim;
			if(futimens(fd, times) < 0){      //sync mtime
				fprintf(stderr, "sync mtime fail\n");
			}
			close(fd);
			return 1;
		}
	}
	else{   //maybe file has existed
		if(S_ISDIR(res.message.body.stat.st_mode)){
			//fprintf(stderr, "path is %s\n", path);
			/*(struct timespec times[2];
			int fd;
			if((fd = open(path, O_RDWR)) < 0){
				fprintf(stderr, "open error\n");
			}
			times[0] = meta->message.body.stat.st_atim;
			times[1] = meta->message.body.stat.st_mtim;
			if(futimens(fd, times) < 0){
				fprintf(stderr, "sync mtime fail\n");
			}
			close(fd);
			if(chmod(path, meta->message.body.stat.st_mode) < 0){
				fprintf(stderr, "sync permission fail\n");
			}*/
			res.message.header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
			header = res.message.header;
			if(!send_message(conn_fd, &header, sizeof(header))){
				fprintf(stderr, "send_message fail\n");
				return 0;
			}
			return 1;
		}
		if(S_ISREG(res.message.body.stat.st_mode)){
			//fprintf(stderr, "path is %s\n", path);
			md5_file(path, res.message.body.hash);
			if(meta->message.body.hash == res.message.body.hash){
				struct timespec times[2];
				int fd;
				if((fd = open(path, O_RDONLY)) < 0){
					fprintf(stderr, "open error\n");
				}
				times[0] = meta->message.body.stat.st_atim;
				times[1] = meta->message.body.stat.st_mtim;
				if(futimens(fd, times) < 0){
					fprintf(stderr, "sync mtime fail\n");
				}
				close(fd);
				if(chmod(path, meta->message.body.stat.st_mode) < 0){
					fprintf(stderr, "sync permission fail\n");
				}
				res.message.header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
				header = res.message.header;
				if(!send_message(conn_fd, &header, sizeof(header))){
					fprintf(stderr, "send_message fail\n");
					return 0;
				}
				return 1;
			}
			else{
				res.message.header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
				header = res.message.header;
				if(!send_message(conn_fd, &header, sizeof(header))){
					fprintf(stderr, "send_message fail\n");
				}
				csiebox_protocol_file file;
				memset(&file, 0, sizeof(csiebox_protocol_file));
				if(!recv_message(conn_fd, &file, sizeof(file))){  //recv the protocol file from client
					fprintf(stderr, "recv_message fail\n");
				}
				FILE *fptr = fopen(path, "wb");
				char *buf = (char *)malloc(file.message.body.datalen);
				memset(buf, 0, sizeof(buf));
				if(!recv_message(conn_fd, buf, file.message.body.datalen)){  //recv the data of file from client
					fprintf(stderr, "recv_message fail\n");
				}
				size_t n;
				if((n = fwrite(buf, sizeof(char), file.message.body.datalen, fptr)) <= 0){  //write the data into the file in server
					fprintf(stderr, "fwrite the data into the file fail\n");
				}
				free(buf);
				fclose(fptr);
				struct timespec times[2];
				int fd;
				if((fd = open(path, O_RDONLY)) < 0){
					fprintf(stderr, "open error\n");
				}
				times[0] = meta->message.body.stat.st_atim;
				times[1] = meta->message.body.stat.st_mtim;
				if(futimens(fd, times) < 0){   //sync mtime
					fprintf(stderr, "sync mtime fail\n");
				}
				close(fd);
				if(chmod(path, meta->message.body.stat.st_mode) < 0){   //sync permission
					fprintf(stderr, "sync permission fail\n");
				}
				return 1;
			}
		}
		if(S_ISLNK(res.message.body.stat.st_mode)){
			//fprintf(stderr, "path is %s\n", path);
			char buf[PATH_MAX];
			int len;
			memset(buf, 0, PATH_MAX);
			len = readlink(path, buf, PATH_MAX);
			md5(buf, len, res.message.body.hash);
			if(meta->message.body.hash == res.message.body.hash){
				struct timespec times[2];
				int fd;
				if((fd = open(path, O_RDWR)) < 0){
					fprintf(stderr, "open error\n");
				}
				times[0] = meta->message.body.stat.st_atim;
				times[1] = meta->message.body.stat.st_mtim;
				if(futimens(fd, times) < 0){
					fprintf(stderr, "sync mtime fail\n");
				}
				close(fd);
				res.message.header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
				header = res.message.header;
				if(!send_message(conn_fd, &header, sizeof(header))){
					fprintf(stderr, "send_message fail\n");
				}
				return 0;
			}
			else{
				res.message.header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
				header = res.message.header;
				if(!send_message(conn_fd, &header, sizeof(header))){   //send the final meta result back to client
					fprintf(stderr, "send_message fail\n");
				}
				csiebox_protocol_file file;
				memset(&file, 0, sizeof(csiebox_protocol_file));
				if(!recv_message(conn_fd, &file, sizeof(file))){  //recv the protocol file from client
					fprintf(stderr, "recv_message fail\n");
				}
				char *buf = (char *)malloc(file.message.body.datalen);
				memset(buf, 0, sizeof(buf));
				if(!recv_message(conn_fd, buf, file.message.body.datalen)){  //recv the symlink content from the client
					fprintf(stderr, "recv_message fail\n");
				}
				symlink(buf, path);
				struct timespec times[2];
				int fd;
				if((fd = open(path, O_RDWR)) < 0){
					fprintf(stderr, "open error\n");
				}
				times[0] = meta->message.body.stat.st_atim;
				times[1] = meta->message.body.stat.st_mtim;
				if(futimens(fd, times) < 0){  //sync mtime
					fprintf(stderr, "sync mtime fail\n");
				}
				close(fd);
				return 1;
			}
		}
	}	
}

//sync hardlink from the client
static int sync_hardlink(csiebox_server *server, int conn_fd, csiebox_protocol_hardlink *hardlink){
	char otherhardlinkpath[PATH_MAX];
	memset(otherhardlinkpath, 0, sizeof(otherhardlinkpath));
	char regfilepath[PATH_MAX];
	memset(regfilepath, 0, sizeof(regfilepath));
	strcpy(otherhardlinkpath, server->arg.path);
	strcat(otherhardlinkpath, "/");
	strcat(otherhardlinkpath, server->client[conn_fd]->account.user);
	strcpy(regfilepath, server->arg.path);
	strcat(regfilepath, "/");
	strcat(regfilepath, server->client[conn_fd]->account.user);
	char regfilepathtmp[PATH_MAX];
	memset(regfilepathtmp, 0, sizeof(regfilepathtmp));
	if(!recv_message(conn_fd, regfilepathtmp, hardlink->message.body.targetlen)){  //since the first path sent from client is serverpath(regfile's path), regfilepath correpond with serverpath
		fprintf(stderr, "recv_message fail\n");
	}
	strcat(regfilepath, regfilepathtmp);
	char otherhardlinkpathtmp[PATH_MAX];
	memset(otherhardlinkpathtmp, 0, sizeof(otherhardlinkpathtmp));
	if(!recv_message(conn_fd, otherhardlinkpathtmp, hardlink->message.body.srclen)){    //since the second path sent from client is serverhardlinkpath(other hardlink's path), otherhardlinkpath correspond with serverhardlinkpath
		fprintf(stderr, "recv_message fail\n");
	}
	strcat(otherhardlinkpath, otherhardlinkpathtmp);
	int error = 0;
	if(link(regfilepath, otherhardlinkpath) < 0){
		fprintf(stderr, "link fail\n");
		error = 1;
	}
	csiebox_protocol_header header;
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK;
	if(error){
		header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
	}
	else{
		header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	} 
	if(!send_message(conn_fd, &header, sizeof(header))){
		fprintf(stderr, "send_message fail\n");
		return 0;
	}
	else{
		return 1;
	}
}

//sync rm from client
static int sync_rm(csiebox_server *server, int conn_fd, csiebox_protocol_rm *rm){
	char path[PATH_MAX];
	memset(path, 0, sizeof(path));
	strcpy(path, server->arg.path);
	strcat(path, "/");
	strcat(path, server->client[conn_fd]->account.user);
	char pathtmp[PATH_MAX];
	memset(pathtmp, 0, sizeof(pathtmp));
	if(!recv_message(conn_fd, pathtmp, rm->message.body.pathlen)){
		fprintf(stderr, "recv_message fail\n");
	}
	strcat(path, pathtmp);
	fprintf(stderr, "path is %s\n", path);
	struct stat sb;
	int error = 1;
	//fprintf(stderr, "path is %s\n", path);
	if(lstat(path, &sb) < 0){
		fprintf(stderr, "lstat fail\n");
	}
	else{
		if(S_ISDIR(sb.st_mode)){
			if(rmdir(path) < 0){
				fprintf(stderr, "rmdir %s fail\n", path);
			}
			error = 0;
		}
		if(S_ISREG(sb.st_mode)){
			if(unlink(path) < 0){
				fprintf(stderr, "unlink %s fail\n", path);
			}
			error = 0;
		}
		if(S_ISLNK(sb.st_mode)){
			if(unlink(path) < 0){
				fprintf(stderr, "unlink %s fail\n", path);
			}
			error = 0;
		}
	}
	csiebox_protocol_header header;
	header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
	header.res.op = CSIEBOX_PROTOCOL_OP_RM;
	if(error){
		header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
	}
	else{
		header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
	}
	if(!send_message(conn_fd, &header, sizeof(header))){
		fprintf(stderr, "send_message fail\n");
		return 0;
	}
	else{
		return 1;
	}
}

//read config file, and start to listen
void csiebox_server_init(
  csiebox_server** server, int argc, char** argv) {
  csiebox_server* tmp = (csiebox_server*)malloc(sizeof(csiebox_server));
  if (!tmp) {
    fprintf(stderr, "server malloc fail\n");
    return;
  }
  memset(tmp, 0, sizeof(csiebox_server));
  if (!parse_arg(tmp, argc, argv)) {
    fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
    free(tmp);
    return;
  }
  int fd = server_start();
  if (fd < 0) {
    fprintf(stderr, "server fail\n");
    free(tmp);
    return;
  }
  tmp->client = (csiebox_client_info**)
      malloc(sizeof(csiebox_client_info*) * getdtablesize());
  if (!tmp->client) {
    fprintf(stderr, "client list malloc fail\n");
    close(fd);
    free(tmp);
    return;
  }
  memset(tmp->client, 0, sizeof(csiebox_client_info*) * getdtablesize());
  tmp->listen_fd = fd;
  *server = tmp;
}

//wait client to connect and handle requests from connected socket fd
//===============================
//		TODO: you need to modify code in here and handle_request() to support I/O multiplexing
//===============================
int csiebox_server_run(csiebox_server* server) {
  int conn_fd, conn_len;
  struct sockaddr_in addr;
  fd_set master;
  fd_set reader_fds;
  int fdmax;
  FD_ZERO(&master);
  FD_ZERO(&reader_fds);
  FD_SET(server->listen_fd, &master);
  fdmax = server->listen_fd;
  struct timeval timeout;
  while (1) {
    reader_fds = master;
    memset(&addr, 0, sizeof(addr));
    conn_len = 0;
    //puts("03");
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
    if(select(fdmax+1, &reader_fds, NULL, NULL, &timeout) == -1){
	fprintf(stderr, "select error\n");
    }
    //puts("04");
    int i;
    for(i = 0; i <= fdmax; i++){
	if(FD_ISSET(i, &reader_fds)){
		if(i == server->listen_fd){
			// waiting client connect
    			conn_fd = accept(server->listen_fd, (struct sockaddr*)&addr, (socklen_t*)&conn_len);
    			if (conn_fd < 0) {
      				if (errno == ENFILE) {
          				fprintf(stderr, "out of file descriptor table\n");
          				continue;
        			} else if (errno == EAGAIN || errno == EINTR) {
          				continue;
        			} else {
          				fprintf(stderr, "accept err\n");
          				fprintf(stderr, "code: %s\n", strerror(errno));
          				break;
        			}
    			}
			else{
				FD_SET(conn_fd, &master);
				if(conn_fd > fdmax){
					fdmax = conn_fd;
				}
				fprintf(stderr, "new client connect\n");
			}
		}
		else{
			// handle request from connected socket fd
			fprintf(stderr, "server->client[%d]->account.user is %s\n", i, server->client[i]->account.user);
			if(handle_request(server, i) == 0){
				fprintf(stderr, "FD_CLR\n");
				FD_CLR(i, &master);
			}
		}
	}
     }
  }
  return 1;
}

void csiebox_server_destroy(csiebox_server** server) {
  csiebox_server* tmp = *server;
  *server = 0;
  if (!tmp) {
    return;
  }
  close(tmp->listen_fd);
  int i = getdtablesize() - 1;
  for (; i >= 0; --i) {
    if (tmp->client[i]) {
      free(tmp->client[i]);
    }
  }
  free(tmp->client);
  free(tmp);
}

//read config file
static int parse_arg(csiebox_server* server, int argc, char** argv) {
  if (argc != 2) {
    return 0;
  }
  FILE* file = fopen(argv[1], "r");
  if (!file) {
    return 0;
  }
  fprintf(stderr, "reading config...\n");
  size_t keysize = 20, valsize = 20;
  char* key = (char*)malloc(sizeof(char) * keysize);
  char* val = (char*)malloc(sizeof(char) * valsize);
  ssize_t keylen, vallen;
  int accept_config_total = 2;
  int accept_config[2] = {0, 0};
  while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
    key[keylen] = '\0';
    vallen = getline(&val, &valsize, file) - 1;
    val[vallen] = '\0';
    fprintf(stderr, "config (%zd, %s)=(%zd, %s)\n", keylen, key, vallen, val);
    if (strcmp("path", key) == 0) {
      if (vallen <= sizeof(server->arg.path)) {
        strncpy(server->arg.path, val, vallen);
        accept_config[0] = 1;
      }
    } else if (strcmp("account_path", key) == 0) {
      if (vallen <= sizeof(server->arg.account_path)) {
        strncpy(server->arg.account_path, val, vallen);
        accept_config[1] = 1;
      }
    }
  }
  free(key);
  free(val);
  fclose(file);
  int i, test = 1;
  for (i = 0; i < accept_config_total; ++i) {
    test = test & accept_config[i];
  }
  if (!test) {
    fprintf(stderr, "config error\n");
    return 0;
  }
  return 1;
}


//this is where the server handle requests, you should write your code here
static int handle_request(csiebox_server* server, int conn_fd) {
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  if (recv_message(conn_fd, &header, sizeof(header)) > 0) {
	//puts("00");
    if (header.req.magic != CSIEBOX_PROTOCOL_MAGIC_REQ) {
	//puts("02");
      return 0;
    }
    switch (header.req.op) {
      case CSIEBOX_PROTOCOL_OP_LOGIN:
        fprintf(stderr, "login\n");
        csiebox_protocol_login req;
        if (complete_message_with_header(conn_fd, &header, &req)) {
          login(server, conn_fd, &req);
	  csiebox_protocol_header header;
	  memset(&header, 0, sizeof(header));
	  fprintf(stderr, "server->client[conn_fd]->account.user is %s\n", server->client[conn_fd]->account.user);
	  if(!recv_message(conn_fd, &header, sizeof(header))){
		fprintf(stderr, "recv_message fail\n");
	  }
	  if(header.req.status != CSIEBOX_PROTOCOL_STATUS_OK){
		hash serverhash;
		serverhash.node = NULL;
		hash* hash_ptr_forhdlink = &serverhash;
		if(init_hash_forhdlink(hash_ptr_forhdlink, filemaxno) == 0){
			fprintf(stderr, "hash fail");
		}
		char path_t[PATH_MAX];
		memset(path_t, 0, sizeof(path_t));
		strcpy(path_t, server->arg.path);
		strcat(path_t, "/");
		strcat(path_t, server->client[conn_fd]->account.user);
		fprintf(stderr, "start traversalsdir\n");
		traversalsdir(server, conn_fd, path_t, hash_ptr_forhdlink);
		fprintf(stderr, "traversalsdir is over\n");
	  }
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_META:
        fprintf(stderr, "sync meta\n");
        csiebox_protocol_meta meta;
        if (complete_message_with_header(conn_fd, &header, &meta)) {
		fprintf(stderr, "sync_meta\n");
		if(sync_meta_and_file(server, conn_fd, &meta) == 1){
			fprintf(stderr, "sync meta and file successful\n");
		}
		else{
			fprintf(stderr, "sync meta and file fail\n");
		}
          //====================
          //        TODO: here is where you handle sync_meta and even sync_file request from client
          //====================
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK:
        fprintf(stderr, "sync hardlink\n");
        csiebox_protocol_hardlink hardlink;
        if (complete_message_with_header(conn_fd, &header, &hardlink)) {
		if(sync_hardlink(server, conn_fd, &hardlink) == 1){
			fprintf(stderr, "sync hardlink successful\n");
		}
		else{
			fprintf(stderr, "sync hardlink fail\n");
		}
          //====================
          //        TODO: here is where you handle sync_hardlink request from client
          //====================
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_END:
        fprintf(stderr, "sync end\n");
        csiebox_protocol_header end;
          //====================
          //        TODO: here is where you handle end of synchronization request from client
          //====================
        break;
      case CSIEBOX_PROTOCOL_OP_RM:
        fprintf(stderr, "rm\n");
        csiebox_protocol_rm rm;
        if (complete_message_with_header(conn_fd, &header, &rm)) {
		if(sync_rm(server, conn_fd, &rm) == 1){
			fprintf(stderr, "sync rm successful\n");
		}
		else{
			fprintf(stderr, "sync rm fail\n");
		}
          //====================
          //        TODO: here is where you handle rm file or directory request from client
          //====================
        }
        break;
      default:
        fprintf(stderr, "unknown op %x\n", header.req.op);
        break;
    }
    return 1;
  }
  else{
     fprintf(stderr, "end of connection\n");
     logout(server, conn_fd);
     return 0;
  }
}

//open account file to get account information
static int get_account_info(
  csiebox_server* server,  const char* user, csiebox_account_info* info) {
  FILE* file = fopen(server->arg.account_path, "r");
  if (!file) {
    return 0;
  }
  size_t buflen = 100;
  char* buf = (char*)malloc(sizeof(char) * buflen);
  memset(buf, 0, buflen);
  ssize_t len;
  int ret = 0;
  int line = 0;
  while ((len = getline(&buf, &buflen, file) - 1) > 0) {
    ++line;
    buf[len] = '\0';
    char* u = strtok(buf, ",");
    if (!u) {
      fprintf(stderr, "illegal form in account file, line %d\n", line);
      continue;
    }
    if (strcmp(user, u) == 0) {
      memcpy(info->user, user, strlen(user));
      char* passwd = strtok(NULL, ",");
      if (!passwd) {
        fprintf(stderr, "illegal form in account file, line %d\n", line);
        continue;
      }
      md5(passwd, strlen(passwd), info->passwd_hash);
      ret = 1;
      break;
    }
  }
  free(buf);
  fclose(file);
  return ret;
}

//handle the login request from client
static void login(
  csiebox_server* server, int conn_fd, csiebox_protocol_login* login) {
  int succ = 1;
  csiebox_client_info* info =
    (csiebox_client_info*)malloc(sizeof(csiebox_client_info));
  memset(info, 0, sizeof(csiebox_client_info));
  if (!get_account_info(server, login->message.body.user, &(info->account))) {
    fprintf(stderr, "cannot find account\n");
    succ = 0;
  }
  if (succ &&
      memcmp(login->message.body.passwd_hash,
             info->account.passwd_hash,
             MD5_DIGEST_LENGTH) != 0) {
    fprintf(stderr, "passwd miss match\n");
    succ = 0;
  }

  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
  header.res.op = CSIEBOX_PROTOCOL_OP_LOGIN;
  header.res.datalen = 0;
  if (succ) {
    if (server->client[conn_fd]) {
      free(server->client[conn_fd]);
    }
    info->conn_fd = conn_fd;
    server->client[conn_fd] = info;
    header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
    header.res.client_id = info->conn_fd;
    char* homedir = get_user_homedir(server, info);
    mkdir(homedir, DIR_S_FLAG);
    free(homedir);
  } else {
    header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
    free(info);
  }
  send_message(conn_fd, &header, sizeof(header));
}

static void logout(csiebox_server* server, int conn_fd) {
  free(server->client[conn_fd]);
  server->client[conn_fd] = 0;
  close(conn_fd);
}

static char* get_user_homedir(
  csiebox_server* server, csiebox_client_info* info) {
  char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
  memset(ret, 0, PATH_MAX);
  sprintf(ret, "%s/%s", server->arg.path, info->account.user);
  return ret;
}

