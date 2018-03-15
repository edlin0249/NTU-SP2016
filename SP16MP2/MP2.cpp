#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
/* "readdir" etc. are defined here. */
#include <dirent.h>
/* limits.h defines "PATH_MAX". */
#include <limits.h>
#include <sys/stat.h>
/* List the files in "dir_name". */
#include <fcntl.h>
#include <unistd.h>
#define BUFFSIZE 4096
static void
list_dir (const char * dir_name)
{
    DIR * d;

    /* Open the directory specified by "dir_name". */

    d = opendir (dir_name);

    /* Check it was opened. */
    if (! d) {
        fprintf (stderr, "Cannot open directory '%s': %s\n",
                 dir_name, strerror (errno));
        exit (EXIT_FAILURE);
    }
    while (1) {
        struct dirent * entry;
        const char * d_name;

        /* "Readdir" gets subsequent entries from "d". */
        entry = readdir (d);
        if (! entry) {
            /* There are no more entries in this directory, so break
               out of the while loop. */
            break;
        }
        d_name = entry->d_name;
        /* Print the name of the file and directory. */
	if (strcmp (d_name, "..") != 0 && strcmp (d_name, ".") != 0) {
        	int path_length;
        	char path[PATH_MAX + 1];
        	path_length = snprintf (path, PATH_MAX, "%s/%s", dir_name, d_name);
        	if (path_length >= PATH_MAX) {
        		fprintf (stderr, "Path length has got too long.\n");
        		exit (EXIT_FAILURE);
        	}
		if(d_name[0] != '.'){
			printf("%s\n", path+7);
			if(entry->d_type == DT_DIR){
				char otherpath[PATH_MAX + 1] = "server/";
				strcat(otherpath, path+7);
				mkdir(otherpath, 0777);
				list_dir(path);
			}
			if(entry->d_type == DT_REG){
				char otherpath[PATH_MAX + 1] = "server/";
				strcat(otherpath, path+7);		
				FILE* fptr1 = fopen(path, "rb");
				FILE* fptr2 = fopen(otherpath, "wb");
				size_t n;
				char buf[BUFFSIZE];
				memset(buf, 0, BUFFSIZE);
				while((n = fread(buf, sizeof(char), BUFFSIZE, fptr1)) > 0){
					size_t tmp;
					tmp = fwrite(buf, sizeof(char), n, fptr2);
				}
				fclose(fptr1);
				fclose(fptr2);
			}
			if(entry->d_type == DT_LNK){
				char otherpath[PATH_MAX + 1] = "server/";
				strcat(otherpath, path+7);
				char buf[BUFFSIZE];
				memset(buf, 0, BUFFSIZE);
				readlink(path, buf, BUFFSIZE);
				symlink(buf, otherpath);
			}
		}
	}
    }
    /* After going through all the entries, close the directory. */
    if (closedir (d)) {
        fprintf (stderr, "Could not close '%s': %s\n", dir_name, strerror (errno));
        exit (EXIT_FAILURE);
    }
    return;
}

int main ()
{
    list_dir ("client");
    return 0;
}
