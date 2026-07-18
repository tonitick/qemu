#ifndef RAND_UTIL_H
#define RAND_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// Random helpers backed by /dev/urandom (Linux-specific). Non-reproducible: each call
// reads fresh entropy. get_random_float/double sample uniformly in [min, max].

unsigned char get_random_byte(void);
unsigned char get_random_byte(void) {
	//This will make things linux specific, but lot of hardcoded things.
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        perror("fopen /dev/urandom");
        exit(EXIT_FAILURE);
    }

    unsigned char byte;
    size_t result = fread(&byte, 1, 1, fp);
    fclose(fp);

    if (result != 1) {
        fprintf(stderr, "Failed to read from /dev/urandom\n");
        exit(EXIT_FAILURE);
    }

    return byte;
}

uint32_t get_random_word(void);
uint32_t get_random_word(void) {
    //This will make things linux specific, but lot of hardcoded things.
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        perror("fopen /dev/urandom");
        exit(EXIT_FAILURE);
    }

    uint32_t word;
    size_t result = fread(&word, sizeof(uint32_t), 1, fp);
    fclose(fp);

    if (result != 1) {
        fprintf(stderr, "Failed to read from /dev/urandom\n");
        exit(EXIT_FAILURE);
    }

    return word;
}

float get_random_float(float min, float max);
float get_random_float(float min, float max) {
    // Generate a random float in the range [min, max]
    unsigned int random_word = get_random_word();
    return min + (random_word / (float)UINT32_MAX) * (max - min);
}

double get_random_double(double min, double max);
double get_random_double(double min, double max) {
    // Generate a random double in the range [min, max]
    unsigned int random_word = get_random_word();
    return (double)(((float)min + (random_word / (float)UINT32_MAX) * ((float)max - (float)min)));
}

#endif // RAND_UTIL_H
