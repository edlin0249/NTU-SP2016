#include <stdio.h>

int main(int argc, char* argv[]){
	FILE* fptr1 = fopen(argv[1], "rb");
	FILE* fptr2 = freopen(argv[2], "wb", stdout);
	char c;
	char vowelstr[10] = {'a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U'};
	int vowelcnt = 0;
	while((c = fgetc(fptr1)) != EOF){
		for(int i = 0; i < 9; i++){
			if(c == vowelstr[i]){
				vowelcnt++;
				break;
			}
		}
	}
	printf("%d\n", vowelcnt);
	fclose(fptr1);
	fclose(fptr2);
	return 0;
}
