#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    //ip_adress for the hash function to seperate different users
    char *ip_address;
    //start_time to reset the 10 minute window and find the derivative of different data points per 1 minute to detect outlier behavior
    time_t last_update_time;
    //total_requests to find the total requests within a 10 minute window
    long total_requests;
    //total_bytes to find the bytes sent within a 10 minute window
    double total_bytes;
    //errors_hit to detect how many times they hit a 400 or 401 error to see how many times they tried to login and got denied
    long errors_hit;
} user_profile;

//magnitude_calc(): this function will take in the requests, bytes sent, and errors and return the intensity of the users activity
double magnitude_calc(long requests, double bytes, long errors);
//this function will handle file i/o and keeping track of all the users
long parse_logs(FILE *logs, user_profile** users, long bookmark, char* log_line, long min_rotations);
//this function will handle updates and resets by updating the normal distribution and getting insights from the data
int update_statistics(user_profile** users, long capacity, long *last_1min_update, long *start_min, double *mean, double *variance, double *std_dev, double* sum_of_squares, double* sum_of_magnitude, long *min_rotations);
//hash(): the hash function will use an ip adress as input to hash the profiles array so we can find different users in O(1) lookup time without looping through the massive array to find someone
long hash(char *ip_address);
//outlier_detector(): this function will create a bell curve with all the data and call the tracker() function if it detects anything 3 standard deviations away from the mean
void outlier_detector(double z_score, char *ip_address, user_profile** users);
//tracker(): this function will trace the outlier to find the ip adress then hash to the correct user and use the data to define a "behevior" by calling behavior() then formatting it and updating the output csv with this user
void tracker(char *ip_address, user_profile** users);
//behavior() this function will use a bell curve where x is the number of requests and y is the number of bytes sent so we can see if the gradient vector supports a "brute force" attack or a "data export" attack
int behavior(double requests, double bytes, long errors);

//global variables
#define BYTE_DIVISOR 1000.0
#define REQUEST_DIVISOR 10.0
#define PI 3.14159265358979323846
const double LOG_SIZE = 1024;
double mean = 0;
double variance = 0;
double std_dev = 0;
long resets = 0;
long reseted_resets = 0;
long user_count = 0;
long capacity = 5000;
long min_rotations = 0;

//initialize time variables
time_t now_sec;
struct tm *t;
long prev_min = -1;
long current_min;

int main() {
    //allocate memory for the users array
    user_profile** users = calloc(capacity, sizeof(user_profile*));
    if (users == NULL) {
        return 1;
    }

    //initialize time in seconds
    now_sec = time(NULL);
    //break it down into an hours, minutes, seconds format
    t = localtime(&now_sec);
    //switch the time to minutes
    current_min = t->tm_min;

    //initialize other time variables
    long last_1min_update = -1;
    long start_min = current_min;
    long min_check = -1;

    //initialize sums needed for mean, variance, and to load data into normal distribution
    double sum_of_magnitude = 0;
    double sum_of_squares = 0;

    //open the server_logs csv for the loop to acsess the data
    FILE *logs = fopen("server_logs.csv", "r");
    if (logs == NULL) {
        printf("Error: Could not open server_logs.csv\n");
        free(users);
        return 1;
    }

    //initialize the output file
    FILE *f = fopen("alert.csv", "w");
    if (f != NULL) {
        fprintf(f, "Current Minute, IP Address, Attack Type, Priority\n");
        fclose(f);
    }

    //create a buffer to catch each line of data
    char *log_line = malloc(LOG_SIZE);
    //create a bookmark variable to resume the file where it left off when looking for new data
    long bookmark = 0;

    printf("System Online. Monitoring for outliers...\n");

    //this loop will enforce a 10 minute window and a 1 minute window
    while (true) {
        //Update current time
        now_sec = time(NULL);
        t = localtime(&now_sec);
        current_min = t->tm_min;

        if (current_min != min_check) {
            //call function to parse data
            bookmark = parse_logs(logs, users, bookmark, log_line, min_rotations);
            //update the normal distribution using the new data
            update_statistics(users, capacity, &last_1min_update, &start_min, &mean, &variance, &std_dev, &sum_of_squares, &sum_of_magnitude, &min_rotations);
            //update minute check to make sure this if statment is not true every second
            min_check = current_min;
            //print an update to the terminal every minute to show the system is working
            printf("Stats Updated: Mean=%.2f, StdDev=%.2f\n", mean, std_dev);
        }
        //Allow the cpu to rest for .1 seconds to avoid frying the cpu
        usleep(100000);
    }
}

double magnitude_calc(long requests, double bytes, long errors) {
    //normalize the data for the requests and bytes to not make the errors look "invisible"
    double norm_requests = (double)requests / REQUEST_DIVISOR;
    double norm_bytes = bytes / BYTE_DIVISOR;
    //use the pythagrean theroem to find the magnitude
    return sqrt((pow(norm_requests, 2)) + (pow(norm_bytes, 2)) + (pow((double)errors, 2)));
}

long parse_logs(FILE *logs, user_profile** users, long bookmark, char* log_line, long min_rotations) {
    //initialize variables
    double ts_dummy;
    char ip_buffer[64];
    char request_buffer[256];
    long index;
    int error_status;
    long bytes_val;
    user_profile* current_user;

    //find the spot the file last left off on
    fseek(logs, bookmark, SEEK_SET);

    while (fgets(log_line, LOG_SIZE, logs) != NULL) {
        // Use sscanf to robustly parse the CSV fields. 
        // This handles varying timestamp lengths and long URLs much better than strtok.
        if (sscanf(log_line, "%lf,%63[^,],%255[^,],%d,%ld", 
                   &ts_dummy, ip_buffer, request_buffer, &error_status, &bytes_val) != 5) {
            continue;
        }

        //create array index for current user by hashing ip_address
        index = hash(ip_buffer);
        long start_index = index;
        
        // Linear probing to handle collisions
        while (users[index] != NULL && strcmp(users[index]->ip_address, ip_buffer) != 0) {
            index = (index + 1) % capacity;
            if (index == start_index) break;
        }

        //check if user is new
        if (users[index] == NULL) {
            //generate place in memory for user
            current_user = malloc(sizeof(user_profile));
            if (current_user == NULL) {
                return bookmark;
            }
            //load users ip_address into array
            current_user->ip_address = strdup(ip_buffer);
            current_user->total_requests = 1;
            //detect how many times they hit a 400 or 401 error
            current_user->errors_hit = (error_status >= 400 && error_status <= 403) ? 1 : 0;
            current_user->total_bytes = (double)bytes_val;
            //remember users last interaction time
            current_user->last_update_time = current_min + (min_rotations * 60);
            //load user into users array
            users[index] = current_user;
        } else {
            //initalize current user
            current_user = users[index];
            if (error_status >= 400 && error_status <= 403) current_user->errors_hit++;
            current_user->total_bytes += (double)bytes_val;
            current_user->total_requests++;
            // USE THE GLOBAL current_min
            current_user->last_update_time = current_min + (min_rotations * 60);
        }
    }
    //get the last logs byte number to act as a "bookmark"
    return ftell(logs);
}

int update_statistics(user_profile** users, long capacity, long *last_1min_update, long *start_min, double *mean_ptr, double *variance_ptr, double *std_dev_ptr, double* sum_of_squares, double* sum_of_magnitude, long *min_rotations) {
    //initialize variables
    double z_score = 0;
    double user_magnitude = 0;
    long active_users = 0;

    //check previous iteration of functions minute
    if (prev_min != -1 && current_min < prev_min) {
        (*min_rotations)++;
    }
    prev_min = current_min;

    //initalize conditional variable
    int elapsed = (int)((current_min - *start_min + 60) % 60);

    //check if its a 10 minute window
    if (elapsed >= 10) {
        //reset each user profile except for the ip address
        for (long i = 0; i < capacity; i++) {
            if (users[i] == NULL) continue;
            users[i]->total_requests = 0;
            users[i]->total_bytes = 0;
            users[i]->errors_hit = 0;
        }
        //reset all data
        *mean_ptr = 0; *variance_ptr = 0; *std_dev_ptr = 0; *sum_of_squares = 0; *sum_of_magnitude = 0;
        //update start time
        *start_min = current_min;
        resets++;
        return 1;
    } else if (elapsed >= 1) {
        //update last_1min_update
        *last_1min_update = current_min;
        //reset sums
        *sum_of_squares = 0; *sum_of_magnitude = 0;

        //calculate mean and active users
        for (long i = 0; i < capacity; i++) {
            if (users[i] == NULL || users[i]->total_requests == 0) continue;
            //calculate the intesnity using the pythagrean theorem
            *sum_of_magnitude += magnitude_calc(users[i]->total_requests, users[i]->total_bytes, users[i]->errors_hit);
            active_users++;
        }

        //check if any users submitted data
        if (active_users < 2) return 2;
        //calculate mean
        *mean_ptr = (*sum_of_magnitude) / active_users;

        for (long i = 0; i < capacity; i++) {
            if (users[i] == NULL || users[i]->total_requests == 0) continue;
            user_magnitude = magnitude_calc(users[i]->total_requests, users[i]->total_bytes, users[i]->errors_hit);
            //subtract the mean from the user magnitude and square it before adding it to the sum_of_squares variable
            *sum_of_squares += pow(user_magnitude - (*mean_ptr), 2);
        }

        //now that we have a mean and a variance we can create a standard deviation
        *variance_ptr = *sum_of_squares / active_users;
        *std_dev_ptr = sqrt(*variance_ptr);

        //the final loop will be plotting data into the outlier_detector() function
        for (long i = 0; i < capacity; i++) {
            if (users[i] == NULL || users[i]->total_requests == 0) continue;
            user_magnitude = magnitude_calc(users[i]->total_requests, users[i]->total_bytes, users[i]->errors_hit);
            //find the z score
            z_score = (*std_dev_ptr > 0.001) ? (user_magnitude - (*mean_ptr)) / (*std_dev_ptr) : 0;
            //give the z score to the function
            outlier_detector(z_score, users[i]->ip_address, users);
        }
        return 2;
    }
    return 0;
}

long hash(char *ip_address) {
    //initialize the prime number accumilator (djb2 style)
    unsigned long total = 5381;
    for (int i = 0; ip_address[i] != '\0'; i++) {
        //multiply it by the accumiltor multiplied by 33 + the ascii value
        total = ((total << 5) + total) + (unsigned char)ip_address[i];
    }
    //return the long with a remainer of capacity
    return (total % capacity);
}

void outlier_detector(double z_score, char *ip_address, user_profile** users) {
    //check if the data point is 3 standard deviations away from the mean
    if (fabs(z_score) >= 1.5) { 
        //call the tracker function to get the outliers current data
        tracker(ip_address, users);
    }
}

void tracker(char *ip_address, user_profile** users) {
    //get the users index then call the hash function to get the users index in the array
    int index = hash(ip_address);
    long start = index;
    // Linear probing search
    while (users[index] != NULL && strcmp(users[index]->ip_address, ip_address) != 0) {
        index = (index + 1) % capacity;
        if (index == start) return;
    }
    //check if user exists
    if (users[index] == NULL) return;

    //find the users data and pass it into the behavior() function
    int bvalue = behavior((double)users[index]->total_requests, users[index]->total_bytes, users[index]->errors_hit);
    //check return value to create file variables
    if (bvalue == 0) return;

    char *attack_type, *prioraty;
    if (bvalue == 1) { attack_type = "brute force"; prioraty = "low"; }
    else if (bvalue == 2) { attack_type = "brute force"; prioraty = "high"; }
    else if (bvalue == 3) { attack_type = "data exfiltration"; prioraty = "low"; }
    else if (bvalue == 4) { attack_type = "data exfiltration"; prioraty = "high"; }
    else { attack_type = "suspicious"; prioraty = "high"; }

    //open file in append mode
    FILE *f = fopen("alert.csv", "a");
    if (f != NULL) {
        //print CSV values
        fprintf(f, "%.2f, %s, %s, %s\n", (double)(resets * 10) + current_min, ip_address, attack_type, prioraty);
        fclose(f);
    }
    //print to terminal
    printf("ALERT: suspicious behavior detected from %s (Type: %s)\n", ip_address, attack_type);
}

int behavior(double requests, double bytes, long errors) {
    //calculate magnitude
    double mag = magnitude_calc((long)requests, bytes, errors);
    if (mag < 0.001) return 0;

    //turn it to a z score
    double z = (std_dev > 0.001) ? (mag - mean) / std_dev : 0;
    //initialize high prioraty boolean variable
    bool high_prioraty = (z >= 5.0);

    //call atan2() function to check angles
    double angle = atan2(bytes, requests) * (180.0 / PI);
    //call acos() function to see how much z influences the M
    double zinf = acos((double)errors / mag) * (180.0 / PI);

    //check for low/high priority brute force
    if ((angle <= 30.0) && (zinf <= 50.0)) return high_prioraty ? 2 : 1;
    //check for low/high priority data exfiltration
    else if ((angle >= 40.0) && (zinf >= 80.0)) return high_prioraty ? 4 : 3;
    //check for high prioraty unknown
    else return 5;
}


