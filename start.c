#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <dirent.h>
#include <sys/vfs.h>
#include <sys/stat.h>


#define MAX_STRING_NUMBER 4 //Number of strings in the file
#define MAX_STRING_SIZE 32 //Maximal number of string length in file
#define RED "\x1B[31m" //Colors for printing
#define NORMAL_COLOR "\x1B[0m" 
#define GREEN "\x1B[32m"
#define MAX 256 //Maximal number of some strings

/*
Program: C ANTIVIRUS
Author: Adam Zientek(311117)
*/


char hash[MAX_STRING_NUMBER][MAX_STRING_SIZE]; //array of hashes as strings
int k = 0; //counter of scanned files
int m = 0; //counter of detected viruses
int om = 0; //counter of omitted files
struct patients //structure describing potential virus file placed in quarantine; in this program those files are referred to as patients
{
	int index; //index of patient file
	int perm[9]; // permissions that patient file had before quarantining; stored in values 0 or 1, they refer to format rwxrwxrwx of permissions
	char old[255]; // original name of patient file
	char new[255]; // name that has been assigned to patient file in quarantine
};
int lncount = 0; // counter of lines in file qinf.txt; it helps to refer to the latest patient in the quarantine or to all patients 
struct patients cur_patient[200]; // maximal number of patients iis 200; when referring to specific patient we use e.x. cur_patient[i]
int q = 0; //defines whether potential viruses should be added to quarantine


/*
Function reading() reads virus hashes from file hash.txt 
and stores them in array of strings hash[][].
*/
int reading(void) {
    FILE *myfile = fopen("hash.txt", "r");
    if (myfile == NULL) {
        printf("Cannot open file.\n");
        return 1;
    }  else {
            char ch;
            int count = 0;
        do
        {
        ch = fgetc(myfile);
        if (ch == '\n') count++;
        } while (ch != EOF);
        rewind(myfile);

        int i;
        for (i = 0; i < count; i++) {
            fscanf(myfile, "%s\n", hash[i]);
        }
	fclose(myfile);
        return 0;
    }
}

/*
Function upgrade_patients() reads data from file kwarantanna/quinf.txt and updates the data to struct patients.
It reads index, permissions, old name, and new name of the patient. Used to load and upgrade quarantine data.
*/
int upgrade_patients(void){
	FILE *myfile = fopen("kwarantanna/qinf.txt", "r");
	if (myfile == NULL) {
        printf("Cannot open file.\n");
        return 1;
       	} else {
            char ch;
            lncount = 0;
        do
        {
        ch = fgetc(myfile);
        if (ch == '\n') lncount++;
        } while (ch != EOF);
        rewind(myfile);

	int i;
	for (i=0; i < lncount; i++) {
	       fscanf(myfile, "%d %s %s %d %d %d %d %d %d %d %d %d\n", &cur_patient[i].index, cur_patient[i].old, cur_patient[i].new, &cur_patient[i].perm[0], &cur_patient[i].perm[1], &cur_patient[i].perm[2], &cur_patient[i].perm[3], &cur_patient[i].perm[4], &cur_patient[i].perm[5], &cur_patient[i].perm[6], &cur_patient[i].perm[7], &cur_patient[i].perm[8]);
	}
	fclose(myfile);
	return 0;
	}
}

/*
Function used to return data about permissions of a patient file called filename,
and then take all the current permissions of a patient file.
*/
int take_permissions(char *filename, int place){

	struct stat fileStat;
	if(stat(filename, &fileStat) < 0) {
		return 2;
	}
	if (place ==0){
		if (fileStat.st_mode & S_IRUSR){
			return 1;
		} else {
			return  0;
		}
	} else if ( place == 1) {
		if (fileStat.st_mode & S_IWUSR) {
			return 1;
		} else {
			return 0;
		}
	} else if (place == 2) {
		if (fileStat.st_mode & S_IXUSR) {
			return 1;
		} else {
			return 0;
		}
	} else if (place == 3){
		if (fileStat.st_mode & S_IRGRP) {
			return 1;
		} else {
			return 0;
		}
	} else if (place == 4) {
		if (fileStat.st_mode & S_IWGRP) {
			return 1;
		} else {
			return 0;
		}
	} else if (place == 5){
		if (fileStat.st_mode & S_IXGRP) {
			return 1;
		} else {
			return 0;
		}
	} else if (place == 6){
		if (fileStat.st_mode & S_IROTH) {
			return 1;
		} else {
			return 0;
		}
	} else if (place == 7){
		if (fileStat.st_mode & S_IWOTH) {
			return 1;
		} else {
			return 0;
		}
	} else if (place == 8){
		if (fileStat.st_mode & S_IXOTH) {
			chmod(filename, 0);
			return 1;
		} else {
			chmod(filename, 0);
			return 0;
		}
	} else {
        return 2;
    }


}

/*
Function return_permissions returns permission of a file by finding the correct line in qinf.txt and calculates 
the right mode for chmod(filename, mode) command by reading permissions from cur_patient[ln].perm[]. 
*/
int return_permissions(char *filename, int ln){


	mode_t mode = 0;

	if (cur_patient[ln].perm[0] == 1) {
		mode |= 0400;
	}

	if (cur_patient[ln].perm[1] == 1) {
		mode |= 0200;
	}

	if (cur_patient[ln].perm[2] == 1) {
		mode |= 0100;
	}

	if (cur_patient[ln].perm[3] == 1) {
		mode |= 0040;
	}

	if (cur_patient[ln].perm[4] == 1) {
		mode |= 0020;
	}

	if (cur_patient[ln].perm[5] == 1) {
		mode |= 0010;
	}

	if (cur_patient[ln].perm[6] == 1) {
		mode |= 0004;
	}

	if (cur_patient[ln].perm[7] == 1) {
		mode |= 0002;
	}

	if (cur_patient[ln].perm[8] == 1) {
		mode |= 0001;
	}

	chmod(filename, mode);
    return 1;
}

/*
Function add_patient is responsible for adding data of a new patient in the qinf.txt file.
*/
int add_patient(char *oldfilename, char *newfilename){
	int i;
	int f = 0;
	for (i =1; i < lncount; i++){
		if (strcmp(oldfilename, cur_patient[i].old) == 0){
			f++;
		}
	}	

	if (f > 0){
		printf("File already in quarantine\n");
		return 2;
	} else {
	FILE *myfile = fopen("kwarantanna/qinf.txt", "a");

	if(myfile ==NULL){
		return 0;
	} else {
		int ze = take_permissions(newfilename, 0);
		int on = take_permissions(newfilename, 1);
		int tw = take_permissions(newfilename, 2);
		int tr = take_permissions(newfilename, 3);
		int fo = take_permissions(newfilename, 4);
		int fi = take_permissions(newfilename, 5);
		int si = take_permissions(newfilename, 6);
		int se = take_permissions(newfilename, 7);
		int ei = take_permissions(newfilename, 8);

		fprintf(myfile, "%d %s %s %d %d %d %d %d %d %d %d %d\n", cur_patient[lncount-1].index+1, oldfilename, newfilename, ze, on, tw, tr, fo, fi, si, se, ei);
	} 
	fclose(myfile);
	upgrade_patients();
	return 1;
	}
}

/*
Function quarantine is the responsible for handling the process of adding 
potential viruses to quarantine folder, adding their data to qinf.txt file,
and putting those data in patients struct.
*/

void quarantine(char * filename){

	upgrade_patients();
	int ret;
	char q_name[] = "../kwarantanna/";
	char *last = strrchr(filename, '/');
	if (last != NULL) {
    		strcat(q_name, last+1);
	} else {
		strcat(q_name, filename);
	}
	
	ret = rename(filename, q_name);
	if ( ret == 0) {
		printf("Success in moving file to quarantine.\n");
		int res =  add_patient(filename, q_name);
		if (res == 1){
			printf("File %s quarantined with success!\n", filename);
		} else {
			printf("File %s could not have been added to quarantine\n", filename);
		}
		upgrade_patients();
	} else {
		printf("Failed to move file to quarantine.\n");
	}
}

/*
Function responsible for scanning a file; it calculates an MD5 hash of a file
and then compares it with hashes from hash.txt file.
*/
int scanning(char *filename){

	unsigned char c[MD5_DIGEST_LENGTH];
       	char d[MD5_DIGEST_LENGTH*2 + 1];
       	int i;
       	FILE *inFile = fopen (filename, "rb");
       	MD5_CTX mdContext;
	int bytes;
	unsigned char data[1024];
	int response = 0;
	size_t n = 32;
	int ogr=0;
	/*I've decided to place a restriction on how many times the MD5_Update is called,
	 because some files are too big, or they put the program into an infinite loop.
	 I compare the hashes that have been generated by this method, so even though they 
	 are not fully correct hashes of a file, they will be correct in terms of comparing
	 them with the hashes that are stored in hash.txt. 
	*/
	if (inFile == NULL){ 
		return 0; //we can't open the file 
       	}

       	MD5_Init (&mdContext);
       	while ((bytes = fread (data, 1, 1024, inFile)) != 0 && ogr<100000 ){
	       	MD5_Update (&mdContext, data, bytes);
		ogr++;
	}
	ogr = 0;
	
	MD5_Final (c,&mdContext);
	for(i = 0; i < MD5_DIGEST_LENGTH; i++){
		snprintf(&d[i*2], 33, "%02x", c[i]);
	}
	fclose (inFile);
	printf("Hash of file %s: %s\n", filename,  d);
	int value;
	int count = sizeof(hash)/sizeof(hash[0]);
	int j;
	for (j = 0; j < count; j++) {
        value = strncmp(d, hash[j], n);
            if(value==0){
		    response++;
            }
        }
	if (response>0){
		return 1;
	} else {
		return 2;
	}

}


/*
Function file_type returns the type of file in form of an unsigned long f_type from statfs() function.
*/
unsigned long file_type(char *filename) {
	struct statfs stt;
	int i = statfs(filename, &stt);
	return stt.f_type;
}


/*
Function many_scans is used to scan whole directories; before scanning the file it checks whether the file is even eligible for
scanning.
*/
void many_scans(char * path)
{
	DIR * d = opendir(path);
	if(d==NULL) return;
	struct dirent * dir;
	int one, two, three;
	int *on, *tw, *tr;

	on = &one;
	tw = &two;
	tr = &three;
	


	while ((dir =readdir(d)) != NULL)
	{
		
		/*
		If file is not a regular file it is not scanned.
		*/		
		if (dir->d_type == DT_SOCK || dir-> d_type == DT_FIFO || dir->d_type == DT_LNK  || dir->d_type == DT_BLK || dir->d_type == DT_CHR ) 
		{
			printf("%sScanning of file %s unavailable: type of file not fit for scanning.%s\n", RED,  dir->d_name, NORMAL_COLOR);
			om++;
		} else if(dir-> d_type == DT_REG)
		{
			

		
			char d_file[255];
			*on = strlen(path);
			*tw = strlen(dir->d_name);
			*tr = *on + *tw + 2;
			snprintf(d_file, *tr, "%s/%s", path, dir->d_name);
	               	unsigned long hextype = file_type(d_file);
					
			/*
			If a file has an f_type (from statfs()) of: PROC_SUPER_MAGIC, 
			DEBUGFS_MAGIC, TRACEFS_MAGIC, SYSFS_MAGIC, or SECURITYFS_MAGIC 
			it won't be scanned either.
			*/
			if (hextype != 0x74726163 && hextype != 0x9fa0 && hextype != 0x64626720 && hextype != 0x62656572 && hextype != 0x73636673){

			printf("Scanning: %s\n", d_file);
			int resp = scanning(d_file);
			if (resp==0){
				printf("Couldn't open file %s : access restricted.\n", d_file);
				om++;
			} else if (resp ==1){
				printf("%sVirus detected in file %s !%s\n", RED, d_file, NORMAL_COLOR);
				k++;
				m++;
				if (q==1){
					quarantine(d_file);
				}
			} else if (resp ==2){
				k++;
			}
			} else {
				printf("%sScanning of file %s unavailable: type of file not fit for scanning.%s\n", RED, dir->d_name, NORMAL_COLOR);
				om++;
			}

		} else if(dir -> d_type == DT_DIR && strcmp(dir->d_name, ".")!=0 && strcmp(dir->d_name, "..")!=0 )
		{
			char d_path[255];
			*on = strlen(path);
			*tw = strlen(dir->d_name);
			*tr = *on + *tw + 2;	
			snprintf(d_path, *tr, "%s/%s", path, dir->d_name);
			if (strcmp(d_path, "../kwarantanna")==0){
				printf("Quarantine directory omitted.\n");
			} else {
			many_scans(d_path);
			}
			
		}
	}
	closedir(d);
}
/*
Function stats() prints out general info about the scanning of a directory.
*/
void stats(char * path){

	if (k == 0){
		printf("The directory did not exist, was empty, or the access is restricted.\n");
	} else {
	int ok = k-m;
	printf("=================================================================================\n");
	printf("Number of files successfully  scanned in a %s  directory: %d\n", path, k);
	printf("%sNumber of files free of viruses: %d%s\n", GREEN,  ok, NORMAL_COLOR);
	printf("%sNumber of infected files: %d%s\n", RED,  m, NORMAL_COLOR);
	printf("Number of omitted files: %d.\n", om);
	printf("=================================================================================\n");
	}
}


/*
Function single scan is responsible for checking whether the file is eligible for scanning,
handling responses of scanning(filename) function and putting potential viruses in the quarantine
if that's what user wants.
 */
int single_scan(char *filename){
	struct stat statinfo;
	int i = stat(filename, &statinfo);
	if (S_ISREG(statinfo.st_mode)) {
		unsigned long hextype = file_type(filename);
		if (hextype != 0x74726163 && hextype != 0x9fa0 && hextype != 0x64626720 && hextype != 0x62656572 && hextype != 0x73636673){
			printf("Scanning file: %s\n", filename);
			int resp = scanning(filename);
			if (resp==0){
				printf("Couldn't open file %s : access restricted.\n", filename);
			} else if (resp ==1){
				printf("%sVirus detected in file %s !%s\n", RED, filename, NORMAL_COLOR);
				if (q==1){
					quarantine(filename);
				}
			} else if (resp ==2){
				printf("%sFile %s is free of viruses!%s\n", GREEN, filename, NORMAL_COLOR); 
			}
		} else {
			printf("File %s is not a regular file.\n", filename);
		}
	} else {
		printf("File %s  is not a regular file or does not exist\n", filename);
	}
	return 0;
}


/*
Function delete_patient deletes patient file form the qinf.txt, because it is being removed from quarantine.
*/

int delete_patient(int line ){

	int ctr = 0;
        char ch;
        FILE *fptr1, *fptr2;
       	char fname[] = "../kwarantanna/qinf.txt";
        char str[MAX], temp[] = "../kwarantanna/temp.txt";
        
	fptr1 = fopen(fname, "r");
        if (!fptr1) 
		{
                printf(" File not found or unable to open the input file!!\n");
                return 1;
        }
        fptr2 = fopen(temp, "w"); // open the temporary file in write mode 
        if (!fptr2) 
		{
                printf("Unable to open a temporary file to write!!\n");
                fclose(fptr1);
                return 1;
        }



	while (!feof(fptr1))
	{
            strncpy(str, "\0", 1);
            fgets(str, MAX, fptr1);
            if (!feof(fptr1)) 
            {
                ctr++;
                /* skip the line at given line number */
                if (ctr != line) 
                {
                    fprintf(fptr2, "%s", str);
                }
            }
        }
        fclose(fptr1);
        fclose(fptr2);
        remove(fname);  		// remove the original file 
        rename(temp, fname); 	// rename the temporary file to original name


        return 0;



}

/*
Function bring_back_my_files is responsible for handling the removal of patient file from quarantine,
moving it to its previous directory, and giving it its permissions back.
*/
void bring_back_my_files(void){

	upgrade_patients();
	int ret;
	int choice;
	int lnfr = 0; //line for removal
	char orgnm[MAX], qnm[MAX]; 
	printf("==========================Quarantine=============================\n");

	printf("Index   Old name of the file            Current name of the file \n");

    for (int i = 1; i < lncount; i++) {
        printf("%d       %s     %s\n", cur_patient[i].index, cur_patient[i].old, cur_patient[i].new);
    }

	printf("Choose the index of a file you want to bring back:\n");
	scanf("%d", &choice);
	if (choice < 1 || choice > cur_patient[lncount-1].index){
		printf("Wrong choice\n");
	} else {
        for (int j = 1; j < lncount; j++) {
            if (choice == cur_patient[j].index) {
                lnfr = j;
            }
        }


        return_permissions(cur_patient[lnfr].new, lnfr);
        ret = rename(cur_patient[lnfr].new, cur_patient[lnfr].old);
        if (ret == 0) {
            printf("File %s brought successfully from quarantine\n", cur_patient[lnfr].old);
        } else {
            printf("Error: file %s could not have been brought back from quarantine\n", cur_patient[lnfr].old);
        }
        delete_patient(lnfr + 1);
    }
	upgrade_patients();
}

/*
Typical main() function, serves as user interface.
*/
int main(void){
	reading();
	upgrade_patients();
	int choice;

	printf("Welcome in our ANTIVIRUS program! Do you want to:\n1. Scan a file.\n2. Scan a directory.\n3. Bring back file from quarantine.\n");
	scanf("%d", &choice);
	if(choice==1){
		int q_choice1;
		char filename[70]; 
		printf("Do you want to place potential viruses in a quarantine?\n1. Yes\n2. No\n");
		scanf("%d", &q_choice1);
		if (q_choice1 == 1){
			q = 1;
		} else if (q_choice1 == 2) {
			q = 0;
		} else {
			printf("Wrong input, assuming you meant 'No'\n");
		}
		printf("Enter the name of the file you want to scan:\n");
		scanf("%s", filename);
		int response = single_scan(filename);
	} else if (choice ==2) {
		char path[70];
		int q_choice2;
		printf("Do you want to place potential viruses in a quarantine?\n1. Yes\n2. No\n");
		scanf("%d", &q_choice2);
		if (q_choice2 == 1){
			q = 1;
		} else if (q_choice2 == 2) {
			q = 0;
		} else {
			printf("Wrong input, assuming you meant 'No'\n");
		}
		printf("Enter the directory you want to scan:\n");
		scanf("%s", path);
		many_scans(path);
		stats(path);
	} else if (choice ==3) {
		bring_back_my_files();
	} else {
		printf("Wrong input\n");
	}
	
	return 0;
}
