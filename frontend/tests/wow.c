#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct
{
	int one;
	char two;
	int three;
} Stuff;

//read from stuff
int do_stuff(Stuff* stuff)
{
	int a = stuff->one;
	int b = stuff->three;
	return a + b;
}

int main()
{
	Stuff s = {.one = 3, .three = 4};

	do_stuff(&s);

	//allocate memory
	Stuff* s2 = malloc(sizeof(Stuff));

	//edit memory
	Stuff** addr_s2 = &s2;
	(*addr_s2)->one = 1;
	(*addr_s2)->two = 'b';

	//memcpy operation
	Stuff s3 = { 0 };
	memcpy(s2, &s3, sizeof(Stuff));
	
	//free
	free(s2);

	return 0;
}
