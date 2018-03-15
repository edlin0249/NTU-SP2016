#include "csiebox_client.h"
#include "hash.h"
#include "csiebox_common.h"
#include "connect.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/inotify.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#define filemaxno 150
#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))
static int parse_arg(csiebox_client* client, int argc, char** argv);
static int login(csiebox_client* client);
static void list_dir (csiebox_client *client, const char * dir_name, hash *hash_ptr, int fd, hash *hash_hdlink);
static int sync_meta(csiebox_client *client, char *path);
static int sync_file(csiebox_client *client, char *path);
static int sync_hdlink(csiebox_client *client, char *path, char *otherpath);
static int sync_rm(csiebox_client *client, char *path);
static int begin_hear(csiebox_client *client, hash *hash_ptr, int fd, hash *hash_hdlnk);
int init_hash_forhlink(hash* h, int n);
int get_from_hash_forhdlink(hash* h, void** contain, int hash_code, char *path); 
int put_into_hash_forhdlink(hash* h, void* contain, int hash_code);
int del_from_hash_forhdlink(hash* h, int hash_code, char *path);
void clean_hash_forhdlink(hash* h);
void destroy_hash_forhdlink(hash* h);
int traversal_hash_forhdlink(hash *h, char *path);
static int sync_meta_and_file_assign2(csiebox_client *client, csiebox_protocol_meta *meta, int fd, hash *hash_ptr, hash *hash_hdlnk);
static int sync_hardlink_assign2(csiebox_client *client, csiebox_protocol_hardlink *hardlink, int fd, hash *hash_hdlnk);
//hash
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
    return 0;
  }
  int same = 0;
  for (; n->next != NULL; n = n->next) {
    if (n->hash_code == hash_code) {
      //printf("n->hash_code = %d, hash_code = %d\n", n->hash_code, hash_code);
      same = 1;
    }
  }
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
    return 1;
  }
  else{
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
//assign2
static int sync_meta_and_file_assign2(csiebox_client *client, csiebox_protocol_meta *meta, int fd, hash *hash_ptr, hash *hash_hdlnk){
	char path[PATH_MAX];
	memset(path, 0, sizeof(path));
	strcpy(path, client->arg.path);
	char pathtmp[PATH_MAX];
	memset(pathtmp, 0, sizeof(pathtmp));
	if(!recv_message(client->conn_fd, pathtmp, meta->message.body.pathlen)){  //second recv path from server
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
			int wd = inotify_add_watch(fd, path, IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY | IN_IGNORED);
			//char *dir_name_tmp;
			//dir_name_tmp = (char*)malloc(PATH_MAX);
			//memset(dir_name_tmp, 0, sizeof(dir_name_tmp));
			//strcpy(dir_name_tmp, path);
			if(put_into_hash(hash_ptr, (void*)path, wd) == 0){
				fprintf(stderr, "put_into_hash fail\n");
			}
			res.message.header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
			header = res.message.header;
			if(!send_message(client->conn_fd, &header, sizeof(header))){  //third send header to server
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
			if(!send_message(client->conn_fd, &header, sizeof(header))){  //third send header to server
				fprintf(stderr, "send_message fail\n");
			}
			csiebox_protocol_file file;
			memset(&file, 0, sizeof(csiebox_protocol_file));
			if(!recv_message(client->conn_fd, &file, sizeof(file))){  //fourth recv file header from server
				fprintf(stderr, "recv_message file fail, wrong!!\n");
			}
			FILE *fptr = fopen(path, "wb");
			char *buf = (char *)malloc(file.message.body.datalen);
			memset(buf, 0, sizeof(buf));
			if(!recv_message(client->conn_fd, buf, file.message.body.datalen)){  //fifth recv file's data from server
				fprintf(stderr, "recv_message fail\n");
			}
			size_t n;
			if((n = fwrite(buf, sizeof(char), file.message.body.datalen, fptr)) <= 0){  //write the data into the file in client
				fprintf(stderr, "fwrite the data into the file fail\n");
			}
			free(buf);
			fclose(fptr);
			struct timespec times[2];
			struct stat sb2;
			if(lstat(path, &sb2) < 0){
				fprintf(stderr, "lstat fail\n");
			}
			if(put_into_hash_forhdlink(hash_hdlnk, (void*)path, sb2.st_ino) == 1){
				fprintf(stderr, "error since existed link's ino is same as the current link\n");
			}
			else{
				fprintf(stderr, "right, not error\n");
			}
			int fd2;
			if((fd2 = open(path, O_RDONLY)) < 0){
				fprintf(stderr, "open error\n");
			}
			times[0] = meta->message.body.stat.st_atim;
			times[1] = meta->message.body.stat.st_mtim;
			if(futimens(fd2, times) < 0){    //sync mtime
				fprintf(stderr, "sync mtime fail\n");
			}
			close(fd2);
			if(chmod(path, meta->message.body.stat.st_mode) < 0){    //sync permission
				fprintf(stderr, "sync permission fail\n");
			}
			return 1;
		}
		if(S_ISLNK(meta->message.body.stat.st_mode)){
			//fprintf(stderr, "path is %s\n", path);
			res.message.header.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
			header = res.message.header;
			if(!send_message(client->conn_fd, &header, sizeof(header))){   //third send header to server
				fprintf(stderr, "send_message fail\n");
			}
			csiebox_protocol_file file;
			memset(&file, 0, sizeof(csiebox_protocol_file));
			if(!recv_message(client->conn_fd, &file, sizeof(file))){  //fourth recv file header from server
				fprintf(stderr, "recv_message fail\n");
			}
			char *buf = (char *)malloc(file.message.body.datalen);
			memset(buf, 0, sizeof(buf));
			if(!recv_message(client->conn_fd, buf, file.message.body.datalen)){  //fifth recv file's data from server
				fprintf(stderr, "recv_message fail\n");
			}
			symlink(buf, path);
			struct timespec times[2];
			int fd2;
			if((fd2 = open(path, O_RDONLY)) < 0){
				fprintf(stderr, "open error\n");
			}
			times[0] = meta->message.body.stat.st_atim;
			times[1] = meta->message.body.stat.st_mtim;
			if(futimens(fd2, times) < 0){      //sync mtime
				fprintf(stderr, "sync mtime fail\n");
			}
			close(fd2);
			return 1;
		}
	}	
}
//sync hardlink assign2
static int sync_hardlink_assign2(csiebox_client *client, csiebox_protocol_hardlink *hardlink, int fd, hash *hash_hdlnk){
	char otherhardlinkpath[PATH_MAX];
	memset(otherhardlinkpath, 0, sizeof(otherhardlinkpath));
	strcpy(otherhardlinkpath, client->arg.path);
	char regfilepath[PATH_MAX];
	memset(regfilepath, 0, sizeof(regfilepath));
	strcpy(regfilepath, client->arg.path);
	char regfilepathtmp[PATH_MAX];
	memset(regfilepathtmp, 0, sizeof(regfilepathtmp));
	if(!recv_message(client->conn_fd, regfilepathtmp, hardlink->message.body.targetlen)){  //second recv clientpath from server, since the first path sent from server is clientpath(regfile's path), regfilepath correpond with clientpath
		fprintf(stderr, "recv_message fail\n");
	}
	strcat(regfilepath, regfilepathtmp);
	char otherhardlinkpathtmp[PATH_MAX];
	memset(otherhardlinkpathtmp, 0, sizeof(otherhardlinkpathtmp));
	if(!recv_message(client->conn_fd, otherhardlinkpathtmp, hardlink->message.body.srclen)){    //third recv clienthardlinkpath form server, since the second path sent from server is clienthardlinkpath(other hardlink's path), otherhardlinkpath correspond with clienthardlinkpath
		fprintf(stderr, "recv_message fail\n");
	}
	strcat(otherhardlinkpath, otherhardlinkpathtmp);
	int error = 0;
	if(link(regfilepath, otherhardlinkpath) < 0){
		fprintf(stderr, "link fail\n");
		error = 1;
	}
	struct stat sb;
	if(lstat(otherhardlinkpath, &sb) < 0){
		fprintf(stderr, "lstat fail\n");
	}
	if(put_into_hash_forhdlink(hash_hdlnk, (void*)otherhardlinkpath, sb.st_ino) == 1){
		fprintf(stderr, "build otherhardlinkpath successful\n");
	}
	else{
		fprintf(stderr, "build otherhardlinkpath error\n");
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
	if(!send_message(client->conn_fd, &header, sizeof(header))){  //fourth send over header to server
		fprintf(stderr, "send_message fail\n");
		return 0;
	}
	else{
		return 1;
	}
}
//assign1
//read config file, and connect to server
static void list_dir (csiebox_client *client, const char * dir_name, hash *hash_ptr, int fd, hash *hash_hdlnk){
    	DIR *d;
	int wd = inotify_add_watch(fd, dir_name, IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY | IN_IGNORED);
	char *dir_name_tmp;
	dir_name_tmp = (char*)malloc(PATH_MAX);
	memset(dir_name_tmp, 0, sizeof(dir_name_tmp));
	strcpy(dir_name_tmp, dir_name);
	if(put_into_hash(hash_ptr, (void*)dir_name_tmp, wd) == 0){
		fprintf(stderr, "put_into_hash fail\n");
	}
	/* Open the directory specified by "dir_name". */
	d = opendir(dir_name);
	/* Check it was opened. */
	if (!d){
		fprintf(stderr, "Cannot open directory '%s': %s\n", dir_name, strerror(errno));
		exit(EXIT_FAILURE);
	}
	while (1) {
        	struct dirent * entry;
        	//const char * d_name;

        	/* "Readdir" gets subsequent entries from "d". */
        	entry = readdir(d);
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
				if(put_into_hash_forhdlink(hash_hdlnk, (void*)path, sb.st_ino) == 1){
					if(get_from_hash_forhdlink(hash_hdlnk, (void**)&otherpath, sb.st_ino, path) == 0){   //path for other hardlink path, otherpath for existing regfile's path
						fprintf(stderr, "get_from_hash_forhdlink fail\n");
					}
					if(sync_hdlink(client, path, otherpath) == 1){  //otherpath is existing reg's path; path is other hardlink path
						printf("sync hardlink is successful\n");
					}
				}
				else{
					//regino[reginosz] = sb.st_ino;
					//reginosz++;
					if(sync_meta(client, path) == 1){
						if(sync_file(client, path) == 1){
							printf("sync meta and file is successful\n");
						}
					}
				}
			}
			else if(S_ISDIR(sb.st_mode)){
				if(sync_meta(client, path) == 1){
					printf("sync meta and file is successful\n");
				}
				list_dir(client, path, hash_ptr, fd, hash_hdlnk);
			}
			else if(S_ISLNK(sb.st_mode)){
				if(sync_meta(client, path) == 1){
					if(sync_file(client, path) == 1){
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

static int sync_meta(csiebox_client *client, char *path){
	csiebox_protocol_meta req;
	char serverpath[PATH_MAX];
	memset(serverpath, 0, sizeof(serverpath));
	//strcat(serverpath, client->arg.user);
	//strcat(serverpath, "/");
	//char pathtmp[PATH_MAX];
	//memset(pathtmp, 0, sizeof(pathtmp));
	//strcpy(pathtmp, client->arg.path);
	int len = strlen(client->arg.path);
	strcpy(serverpath, path+len);
	memset(&req, 0, sizeof(csiebox_protocol_meta));
	req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	req.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
	req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
	req.message.body.pathlen = strlen(serverpath);   //not sure pathlen == strlen(path) ? by own decision
	puts(path);
	puts(serverpath);
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
	if(!send_message(client->conn_fd, &req, sizeof(req))){
		fprintf(stderr, "send req fail\n");
		return 0;
	}
	else{
		fprintf(stderr, "send req successful\n");
	}
	//send file path to server
	if(!send_message(client->conn_fd, serverpath, strlen(serverpath))){
		fprintf(stderr, "send data fail\n");
		return 0;
	}
	else{
		fprintf(stderr, "send data successful\n");
	}
	//receive the message
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	if(recv_message(client->conn_fd, &header, sizeof(header))){
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

static int sync_file(csiebox_client *client, char *path){
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
		if(!send_message(client->conn_fd, &file, sizeof(file))){
			fprintf(stderr, "send data fail\n");
		}
		fseek(fptr, 0, SEEK_SET);
		char *buf = (char *)malloc(file.message.body.datalen);
		memset(buf, 0, sizeof(buf));
		size_t n;
		if((n = fread(buf, sizeof(char), file.message.body.datalen, fptr)) < 0){
			fprintf(stderr, "fread data pointed by fptr fail, n = %z\n", n);
		}
		if(!send_message(client->conn_fd, buf, file.message.body.datalen)){
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
		if(!send_message(client->conn_fd, &file, sizeof(file))){
			fprintf(stderr, "send data fail\n");
		}
		if(!send_message(client->conn_fd, buf, file.message.body.datalen)){
			fprintf(stderr, "send readlink fail\n");
		}
		fprintf(stderr, "sync symbolic link successful\n");
		return 1;
	}
}

static int sync_hdlink(csiebox_client *client, char *path, char *otherpath){ //otherpath is existing reg's path; path is other hardlink path
	csiebox_protocol_hardlink hardlink;
	char serverpath[PATH_MAX];     //serverpath correspond the existing path, so strcat a "reg's path"
	memset(serverpath, 0, sizeof(serverpath));
	char serverhardlinkpath[PATH_MAX];    //serverhardlinkpath correspond the update path of hardlink, so strcat a "path"
	memset(serverhardlinkpath, 0, sizeof(serverhardlinkpath));
	//strcat(serverpath, "user/");
	fprintf(stderr, "client->arg.user = %s\n", client->arg.user);
	//strcat(serverpath, client->arg.user);
	//strcat(serverpath, "/");
	//strcat(serverhardlinkpath, "user/");
	//strcat(serverhardlinkpath, client->arg.user);
	//strcat(serverhardlinkpath, "/");
	int len = strlen(client->arg.path);
	strcpy(serverhardlinkpath, path+len);    //serverhardlink correspond with path(other hardlink's path)
	strcpy(serverpath, otherpath+len);   //serverpath correspond with otherpath(exisintg file's path)
	hardlink.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	hardlink.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK;
	hardlink.message.header.req.datalen = sizeof(hardlink) - sizeof(hardlink.message.header);
	hardlink.message.body.srclen = strlen(serverhardlinkpath);   //srclen represent the length of the path of hardlink in the server
	hardlink.message.body.targetlen = strlen(serverpath);    //targetlen represent the length of the existing path in the server
	//send hardlink req to server
	if(!send_message(client->conn_fd, &hardlink, sizeof(hardlink))){
		fprintf(stderr, "send req fail\n");
	}
	//send target file path(existing path) to server
	if(!send_message(client->conn_fd, serverpath, strlen(serverpath))){   //first send serverpath(regfile's path)
		fprintf(stderr, "send serverpath fail\n");
	}
	//send hardlink path to the server
	if(!send_message(client->conn_fd, serverhardlinkpath, strlen(serverhardlinkpath))){
		fprintf(stderr, "send serverhardlink fail\n");
	}
	//receive if it's successful
	csiebox_protocol_header header;
	memset( &header, 0, sizeof(header) );
	if( recv_message( client->conn_fd, &header, sizeof(header) ) ) {
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

static int sync_rm(csiebox_client *client, char *path){
	fprintf(stderr, "path is %s\n", path);
	csiebox_protocol_rm rm;
	memset(&rm, 0, sizeof(rm));
	rm.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
	rm.message.header.req.op = CSIEBOX_PROTOCOL_OP_RM;
	rm.message.header.req.datalen = sizeof(rm) - sizeof(rm.message.header);
	char serverpath[PATH_MAX];
	memset(serverpath, 0, sizeof(serverpath));
	//strcat(serverpath, client->arg.user);
	//strcat(serverpath, "/");
	int len = strlen(client->arg.path);
	strcpy(serverpath, path+len);
	rm.message.body.pathlen = strlen(serverpath);
	//send rm message req to server
	if(!send_message(client->conn_fd, &rm, sizeof(rm))){
		fprintf(stderr, "send rm req\n");
	}
	//send rm serverpath to server
	if(!send_message(client->conn_fd, serverpath, strlen(serverpath))){
		fprintf(stderr, "send serverpath to server fail\n");
	}
	//receive if rm of server is successful
	csiebox_protocol_header header;
	memset(&header, 0, sizeof(header));
	if(recv_message(client->conn_fd, &header, sizeof(header))){
		if(header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES && header.res.op == CSIEBOX_PROTOCOL_OP_RM){
			if(header.res.status == CSIEBOX_PROTOCOL_STATUS_OK){
				fprintf(stderr, "sync rm to server is successful\n");
				return 1;
			}
			else{
				fprintf(stderr, "sync rm to server is fail\n");
				return 0;
			}
		}
		else{
			fprintf(stderr, "header.res.status and header.res.op is wrong\n");
			return 0;
		}
	}
	else{
		fprintf(stderr, "recv_message fail\n");
		return 0;
	}
}

static int begin_hear(csiebox_client *client, hash *hash_ptr, int fd, hash *hash_hdlnk){
	int length, i = 0;
	//int fd;
	int wd;
	char buffer[EVENT_BUF_LEN];
	memset(buffer, 0, EVENT_BUF_LEN);
	//create a instance and returns a file descriptor
	//fd = inotify_init();
	if (fd < 0) {
		perror("inotify_init");
	}
	//add directory "." to watch list with specified events
	//wd = inotify_add_watch(fd, "../cdirs", IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY);
	while ((length = read(fd, buffer, EVENT_BUF_LEN)) > 0) {
		i = 0;
		while (i < length) {
			struct inotify_event* event = (struct inotify_event*)&buffer[i];
			fprintf(stderr, "event: (%d, %zd, %s)\ntype: ", event->wd, strlen(event->name), event->name);
			fprintf(stderr, "event->mask = %d\n", event->mask);
			char *wd_path;
			char *pathname;
			pathname = (char*)malloc(PATH_MAX);
			memset(pathname, 0, sizeof(pathname));
			if(get_from_hash(hash_ptr, (void**)&wd_path, event->wd) == 0){
				fprintf(stderr, "not in hash\n");
			}
			fprintf(stderr, "wd_path is %s\n", wd_path);
			strcpy(pathname, wd_path);
			//whether it's a dir
			if(event->mask & IN_IGNORED){
				fprintf(stderr, "IN_IGNORED\n");
				fprintf(stderr, "pathname is %s\n", pathname);
				inotify_rm_watch(fd, event->wd);
				fprintf(stderr, "dir's name is %s\n", pathname);
				fprintf(stderr, "pathname is %s\n", pathname);
				if(del_from_hash(hash_ptr, (void**)&pathname, event->wd) == 0){
					fprintf(stderr, "del_from_hash fail\n");
				}
				if(sync_rm(client, pathname) == 1){
					fprintf(stderr, "server rm successful\n");
				}
				else{
					fprintf(stderr, "server rm fail\n");
				}
			}
			else if(event->mask & IN_ISDIR){
				fprintf(stderr, "go to the path is dir\n");
				if(event->mask & IN_CREATE){
					fprintf(stderr, "create dir\n");
					strcat(pathname, "/");
					strcat(pathname, event->name);
					fprintf(stderr, "dir's name is %s\n", pathname);
					int wd;
					wd = inotify_add_watch(fd, pathname, IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY | IN_IGNORED);
					fprintf(stderr, "wd = %d\n", wd);
					if(put_into_hash(hash_ptr, (void*)pathname, wd) == 0){
						fprintf(stderr, "put_into_hash fail\n");
					}
					else{
						fprintf(stderr, "put_into_hash successful, and the pathname is %s\n", pathname);
					}
					struct stat sb;
					if(lstat(pathname, &sb) == -1){
						fprintf(stderr, "lstat fail\n");
					}
					if(sync_meta(client, pathname) == 1){
						fprintf(stderr, "sync_meta successful\n");
					}
					else{
						fprintf(stderr, "sync_meta fail\n");
					}
				}
				if(event->mask & IN_DELETE){
					fprintf(stderr, "dir IN_DELETE\n");
					strcat(pathname, "/");
					strcat(pathname, event->name);
					fprintf(stderr, "dir's name is %s\n", pathname);
					fprintf(stderr, "pathname is %s\n", pathname);
					if(sync_rm(client, pathname) == 1){
						fprintf(stderr, "server rm successful\n");
					}
					else{
						fprintf(stderr, "server rm fail\n");
					}
				}
			}
			else{  //symbolic link, regular file, or other hardlink
				fprintf(stderr, "go to the path is not dir\n");
				strcat(pathname, "/");
				strcat(pathname, event->name);
				int hardlinkkey;
				if(event->mask & IN_CREATE){
					fprintf(stderr, "IN_CREATE\n");
					struct stat sb;
					if(lstat(pathname, &sb) == -1){
						fprintf(stderr, "pathname is %s\n", pathname);
						fprintf(stderr, "lstat fail\n");
					}
					if(S_ISREG(sb.st_mode)){
						int ishd = 0;
						char otherpath[PATH_MAX];
						if(put_into_hash_forhdlink(hash_hdlnk, (void*)pathname, sb.st_ino) == 1){ //int put_into_hash_forhdlink(hash* h, void* contain, int hash_code)
							if(get_from_hash_forhdlink(hash_hdlnk, (void**)&otherpath, sb.st_ino, pathname) == 0){   //int get_from_hash_forhdlink(hash* h, void** contain, int hash_code, char *path)
								fprintf(stderr, "get_from_hash_forhdlink fail\n");
							}
							if(sync_hdlink(client, pathname, otherpath) == 1){
								fprintf(stderr, "sync hardlink is successful\n");
							}
							else{
								fprintf(stderr, "sync hardlink is fail\n");
							}
						}
						else{
							if(sync_meta(client, pathname) == 1){
								if(sync_file(client, pathname) == 1){
									fprintf(stderr, "sync meta and file is successful\n");
								}
								else{
									fprintf(stderr, "sync meta and file is fail\n");
								}
							}
							else{
								fprintf(stderr, "sync meta is fail\n");
							}
						}
					}
					if(S_ISLNK(sb.st_mode)){
						if(sync_meta(client, pathname) == 1){
							if(sync_file(client, pathname) == 1){
								fprintf(stderr, "sync_file successful\n");
							}
							else{
								fprintf(stderr, "sync_file fail\n");
							}
						}
						else{
							fprintf(stderr, "sync_meta fail\n");
						}
					}
				}
				if(event->mask & IN_ATTRIB || event->mask & IN_MODIFY){
					fprintf(stderr, "IN_ATTRIB || IN_MODIFY\n");
					fprintf(stderr, "pathname is %s\n", pathname);
					struct stat sb;
					if(lstat(pathname, &sb) == -1){
						fprintf(stderr, "lstat fail\n");
					}
					if(sync_meta(client, pathname) == 1){
						if(sync_file(client, pathname) == 1){
							fprintf(stderr, "sync_file successful\n");
						}
						else{
							fprintf(stderr, "sync_file fail\n");
						}
					}
					else{
						fprintf(stderr, "sync_meta fail\n");
					}
				}
				if(event->mask & IN_DELETE){
					fprintf(stderr, "IN_DELETE\n");
					fprintf(stderr, "pathname is %s\n", pathname);
					hardlinkkey = traversal_hash_forhdlink(hash_hdlnk, pathname);
					fprintf(stderr, "hardlinkkey is %d\n", hardlinkkey);
					if(hardlinkkey != -1){   //return != -1 is regfile or hdlnk
						if(sync_rm(client, pathname) == 1){
							fprintf(stderr, "sync_rm successful\n");
						}
						else{
							fprintf(stderr, "sync_rm fail\n");
						}
						if(del_from_hash_forhdlink(hash_hdlnk, hardlinkkey, pathname)){  //int del_from_hash_forhdlink(hash* h, int hash_code, char *path)
							fprintf(stderr, "del_from_hash_forhdlink successful\n");
						}
						else{
							fprintf(stderr, "del_from_hash_forhdlink fail\n");
						}
					}
					else{  //return == -1 is symlink
						if(sync_rm(client, pathname) == 1){
							fprintf(stderr, "sync_rm successful\n");
						}
						else{
							fprintf(stderr, "sync_rm fail\n");
						}
					}
				}
      				//i += EVENT_SIZE + event->len;
				free(pathname);
    			}
			i += EVENT_SIZE + event->len;
    			//memset(buffer, 0, EVENT_BUF_LEN);
		}
		memset(buffer, 0, EVENT_BUF_LEN);
  //inotify_rm_watch(fd, wd);
	}
	close(fd);
	return 0;
}

void csiebox_client_init(
  csiebox_client** client, int argc, char** argv) {
  csiebox_client* tmp = (csiebox_client*)malloc(sizeof(csiebox_client));
  if (!tmp) {
    fprintf(stderr, "client malloc fail\n");
    return;
  }
  memset(tmp, 0, sizeof(csiebox_client));
  if (!parse_arg(tmp, argc, argv)) {
    fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
    free(tmp);
    return;
  }
  int fd = client_start(tmp->arg.name, tmp->arg.server);
  if (fd < 0) {
    fprintf(stderr, "connect fail\n");
    free(tmp);
    return;
  }
  tmp->conn_fd = fd;
  *client = tmp;
}

//this is where client sends request, you sould write your code here
int csiebox_client_run(csiebox_client* client) {
  if (!login(client)) {
    fprintf(stderr, "login fail\n");
    return 0;
  }
  fprintf(stderr, "login success\n");
  //====================
  //        TODO: add your client-side code here
	fprintf(stderr, "client->arg.user = %s\n", client->arg.user);
	int isempty = 0;
	DIR *d;
	char *dir_n;
	dir_n = (char*)malloc(PATH_MAX);
	memset(dir_n, 0, sizeof(dir_n));
	fprintf(stderr, "client->arg.path is %s\n", client->arg.path);
	strcpy(dir_n, client->arg.path);
	fprintf(stderr, "dir_n is %s\n", dir_n);
	/* Open the directory specified by "dir_name". */
	d = opendir(dir_n);
	fprintf(stderr, "dir_n is %s\n", dir_n);
	/* Check it was opened. */
	if (!d){
		fprintf(stderr, "Cannot open directory '%s': %s\n", dir_n, strerror(errno));
		exit(EXIT_FAILURE);
	}
	while (1) {
        	struct dirent * entry;
        	//const char * d_name;

        	/* "Readdir" gets subsequent entries from "d". */
        	entry = readdir(d);
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
			path_length = snprintf(path, PATH_MAX, "%s/%s", dir_n, entry->d_name);
			if (path_length >= PATH_MAX) {
				fprintf (stderr, "Path length has got too long.\n");
				exit (EXIT_FAILURE);
			}
			struct stat sb;
			if(lstat(path, &sb) == -1){
				fprintf(stderr, "lstat fail\n");
			}
			else{
				if(S_ISREG(sb.st_mode)){
					isempty++;
				}
				else if(S_ISDIR(sb.st_mode)){
					isempty++;
				}
				else if(S_ISLNK(sb.st_mode)){
					isempty++;
				}
			}
		}
	}
	/* After going through all the entries, close the directory. */
	if(closedir (d)){
		fprintf (stderr, "Could not close '%s': %s\n", dir_n, strerror (errno));
		exit (EXIT_FAILURE);
	}
	free(dir_n);
	fprintf(stderr, "isempty is over\n");
	if(isempty > 0){
		csiebox_protocol_header header;
		memset(&header, 0, sizeof(header));
		header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
		header.req.status = CSIEBOX_PROTOCOL_STATUS_OK;
		if(!send_message(client->conn_fd, &header, sizeof(header))){
			fprintf(stderr, "send_message fail\n");
		}
		hash clienthash;
		clienthash.node = NULL;
		hash* hash_ptr = &clienthash;
		if(init_hash(hash_ptr, filemaxno) == 0){
			fprintf(stderr, "hash fail");
		}
		hash ishardlink;
		ishardlink.node = NULL;
		hash* hash_hdlnk = &ishardlink;
		if(init_hash_forhdlink(hash_hdlnk, filemaxno) == 0){
			fprintf(stderr, "hash fail");
		}
		int fd;
		fd = inotify_init();
		char path_traversal[PATH_MAX];
		memset(path_traversal, 0, sizeof(path_traversal));
		strcpy(path_traversal, client->arg.path);
		fprintf(stderr, "client->arg.path is %s\n", client->arg.path);
		fprintf(stderr, "path_traversal is %s\n", path_traversal);
		list_dir(client, path_traversal, hash_ptr, fd, hash_hdlnk);
		printf("begin_hear\n");
		if(begin_hear(client, hash_ptr, fd, hash_hdlnk) == 0){
			fprintf(stderr, "begin_hear over\n");
		}
	}
	else{
		fprintf(stderr, "relogin\n");
		csiebox_protocol_header header;
		memset(&header, 0, sizeof(header));
		header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
		header.req.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
		if(!send_message(client->conn_fd, &header, sizeof(header))){
			fprintf(stderr, "send_message fail\n");
		}
		int fd;
		fd = inotify_init();
		hash clienthash;
		clienthash.node = NULL;
		hash* hash_ptr = &clienthash;
		if(init_hash(hash_ptr, filemaxno) == 0){
			fprintf(stderr, "hash fail");
		}
		hash ishardlink;
		ishardlink.node = NULL;
		hash* hash_hdlnk = &ishardlink;
		if(init_hash_forhdlink(hash_hdlnk, filemaxno) == 0){
			fprintf(stderr, "hash fail");
		}
		csiebox_protocol_header header2;
		memset(&header2, 0, sizeof(header2));
		while(recv_message(client->conn_fd, &header2, sizeof(header2)) > 0){
			if (header2.req.magic != CSIEBOX_PROTOCOL_MAGIC_REQ) {
				fprintf(stderr, "header.req.magic != CSIEBOX_PROTOCOL_MAGIC_REQ error\n");
			}
    			switch (header2.req.op) {
      				case CSIEBOX_PROTOCOL_OP_SYNC_META:
        				fprintf(stderr, "sync meta\n");
        				csiebox_protocol_meta meta;
        				if (complete_message_with_header(client->conn_fd, &header2, &meta)) {
						fprintf(stderr, "sync_meta\n");
						if(sync_meta_and_file_assign2(client, &meta, fd, hash_ptr, hash_hdlnk) == 1){
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
					if (complete_message_with_header(client->conn_fd, &header2, &hardlink)) {
						if(sync_hardlink_assign2(client, &hardlink, fd, hash_hdlnk) == 1){
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
				default:
					fprintf(stderr, "unknown op %x\n", header.req.op);
				break;
			}
		}
		printf("begin_hear\n");
		if(begin_hear(client, hash_ptr, fd, hash_hdlnk) == 0){
			fprintf(stderr, "begin_hear over\n");
		}
	}
  //====================
  
  
  return 1;
}

void csiebox_client_destroy(csiebox_client** client) {
  csiebox_client* tmp = *client;
  *client = 0;
  if (!tmp) {
    return;
  }
  close(tmp->conn_fd);
  free(tmp);
}

//read config file
static int parse_arg(csiebox_client* client, int argc, char** argv) {
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
  int accept_config_total = 5;
  int accept_config[5] = {0, 0, 0, 0, 0};
  while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
    key[keylen] = '\0';
    vallen = getline(&val, &valsize, file) - 1;
    val[vallen] = '\0';
    fprintf(stderr, "config (%zd, %s)=(%zd, %s)\n", keylen, key, vallen, val);
    if (strcmp("name", key) == 0) {
      if (vallen <= sizeof(client->arg.name)) {
        strncpy(client->arg.name, val, vallen);
        accept_config[0] = 1;
      }
    } else if (strcmp("server", key) == 0) {
      if (vallen <= sizeof(client->arg.server)) {
        strncpy(client->arg.server, val, vallen);
        accept_config[1] = 1;
      }
    } else if (strcmp("user", key) == 0) {
      if (vallen <= sizeof(client->arg.user)) {
        strncpy(client->arg.user, val, vallen);
        accept_config[2] = 1;
      }
    } else if (strcmp("passwd", key) == 0) {
      if (vallen <= sizeof(client->arg.passwd)) {
        strncpy(client->arg.passwd, val, vallen);
        accept_config[3] = 1;
      }
    } else if (strcmp("path", key) == 0) {
      if (vallen <= sizeof(client->arg.path)) {
        strncpy(client->arg.path, val, vallen);
        accept_config[4] = 1;
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

static int login(csiebox_client* client) {
  csiebox_protocol_login req;
  memset(&req, 0, sizeof(req));
  req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  req.message.header.req.op = CSIEBOX_PROTOCOL_OP_LOGIN;
  req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
  memcpy(req.message.body.user, client->arg.user, strlen(client->arg.user));
  md5(client->arg.passwd,
      strlen(client->arg.passwd),
      req.message.body.passwd_hash);
  if (!send_message(client->conn_fd, &req, sizeof(req))) {
    fprintf(stderr, "send fail\n");
    return 0;
  }
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  if (recv_message(client->conn_fd, &header, sizeof(header))) {
    if (header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
        header.res.op == CSIEBOX_PROTOCOL_OP_LOGIN &&
        header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) {
      client->client_id = header.res.client_id;
      return 1;
    } else {
      return 0;
    }
  }
  return 0;
}
