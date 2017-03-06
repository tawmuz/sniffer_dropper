#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

#define USUAL_PAYLOAD_SIZE 1404

double rand_packet_drop(double mean)
{
   double e;

   e = (-1 / mean) * log(1 - drand48());

   return e;
}

int get_drop_count(char *ftp_filename)
{
   int ftp_file_size;
   FILE *ptr_ftp_file;

   if((ptr_ftp_file = fopen(ftp_filename, "r")) == NULL)
   {
      printf("drop_interval_gen: Unable to read ftp file!\n");
      exit(EXIT_FAILURE);
   }
   else 
   {
      printf("drop_interval_gen: Opened ftp file successfully for calculating size.\n");   
   }

   fseek(ptr_ftp_file, 0L, SEEK_END);
   ftp_file_size = ftell(ptr_ftp_file);
   fclose(ptr_ftp_file);

   return (ftp_file_size / USUAL_PAYLOAD_SIZE);
}

int main(int argc, char *argv[])
{
   FILE *ptr_fp_drop;

   int i = get_drop_count(argv[1]);

   srand48(time(0));
   
   if((ptr_fp_drop = fopen("drop_intervals.txt", "wb")) == NULL)
   {
      printf("drop_interval_gen: Unable to create/open file!\n");
      exit(EXIT_FAILURE);
   }
   else 
   {
      printf("drop_interval_gen: Opened drop_intervals.txt successfully for writing.\n");   
   }

   while (i > 0) 
   {
       fprintf(ptr_fp_drop, "%f\n", rand_packet_drop(atoi(argv[2])));
       i--;
   }

   fclose(ptr_fp_drop);
   printf("Drop intervals generated successfully!\n");

   return 0;
}

