#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
uint64_t clienthash[1005];
uint64_t serverhash[1005];
int dptable[1005][1005];
int main(void){
	//printf("-2\n");
	char command[50];
	//char clientfile[120];
	//char serverfile[120];
	//int time = 0;
	//printf("-1\n");
	while(scanf("%s", command) == 1 && (strcmp(command, "exit") != 0)){
		//printf("time = %d\n", time++);
		//printf("cmd = %s\n", command);
		//printf("0\n");
		char filename[110];
		scanf("%s", filename);
		//printf("%s:\n", filename);
		char clientfile[120] = "client/";
		char serverfile[120] = "server/";
		strcat(clientfile, filename);
		strcat(serverfile, filename);
		//printf("clientfile = %s\n", clientfile);
		//printf("serverfile = %s\n", serverfile);
		//printf("1\n");
		memset(clienthash, 0, sizeof(clienthash));
		memset(serverhash, 0, sizeof(serverhash));
		memset(dptable, 0, sizeof(dptable));
		FILE* fptrclient = fopen(clientfile, "r");
		FILE* fptrserver = fopen(serverfile, "r");
		int clientsize = 1;
		char c;
		uint64_t ret = (uint64_t)0;
		if(fptrclient != NULL){  //if clientfile exist , then start the hash of client
			while((c = fgetc(fptrclient)) != EOF){
				if(c != '\n'){
					//printf("%c", c);
					ret = ret * (uint64_t)131 + (uint64_t)c;
				}
				else{   //read '\n'
					//printf("\\n");
					clienthash[clientsize] = ret;
					clientsize++;
					ret = (uint64_t)0;
				}
			}
		}
		//printf("2\n");
		//printf("clienthash:\n");
		//printf("clientsize = %d\n", clientsize);
		//for(uint64_t i = 0; i < clientsize; i++){
		//	printf("%lu%c", clienthash[i], " \n"[i == (clientsize-1LLU)]);
		//}
		int serversize = 1;
		ret = (uint64_t)0;
		if(fptrserver != NULL){  //if serverfile exist , then start the hash of server  
			while((c = fgetc(fptrserver)) != EOF){
				if(c != '\n'){
					ret = ret * (uint64_t)131 + (uint64_t)c;
				}
				else{   //read '\n'
					serverhash[serversize] = ret;
					serversize++;
					ret = (uint64_t)0;
				}
			}
		}
		//printf("3\n");
		//printf("serverhash:\n");
		//printf("serversize = %d\n", serversize);
		//for(uint64_t i = 0; i < serversize; i++){
		//	printf("%llu%c", serverhash[i], " \n"[i == (serversize-1LLU)]);
		//}
		//hash is over, start LCS in line by line
		//printf("clientsize = %d\n", clientsize);
		//printf("serversize = %d\n", serversize);
		clientsize--;
		//printf("clientsize = %d\n", clientsize);
		serversize--;
		//printf("serversize = %d\n", serversize);
		for(int i = 1; i <= clientsize; i++){
			for(int j = 1; j <= serversize; j++){
				if(clienthash[i] == serverhash[j]){
					dptable[i][j] = dptable[i-1][j-1] + 1;
				}
				else{
					dptable[i][j] = (dptable[i-1][j] > dptable[i][j-1] ? dptable[i-1][j] : dptable[i][j-1]);
				}
			}
		}
		//printf("LCS dptable:\n");
		//for(int i = 0; i <= clientsize; i++){
		//	for(int j = 0; j <= serversize; j++){
		//		printf("%d%c", dptable[i][j], " \n"[j == serversize]);
		//	}
		//}
		int LCS = dptable[clientsize][serversize];
		//printf("4\n");
		//printf("LCS = %d\n", LCS);
		printf("%d %d\n", clientsize - LCS, serversize - LCS);
		if(fptrclient != NULL){   //If P exists on the client side
			char cmdcp[200] = "cp ";
			strcat(cmdcp, clientfile);
			strcat(cmdcp, " server/");
			//printf("cmdcp = %s\n", cmdcp);
			system(cmdcp);
		}
		else{     // If P doesn’t exist on the client side
			char cmdrm[200] = "rm ";
			strcat(cmdrm, serverfile);
			//printf("cmdrm = %s\n", cmdrm);
			if(fptrserver != NULL){
				system(cmdrm);
			}
		}
		//printf("5\n");
		//fclose(fptrclient);
		//fclose(fptrserver);
		fflush(stdout);
	}
	return 0;
}

/*
uint64_t hash(const char *s) {
  uint64_t ret = 0;
  while (*s)
    ret = ret * 131 + *s++;
  return ret;
}
*/
