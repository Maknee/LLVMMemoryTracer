#include <stdio.h>
#include <stdlib.h>
typedef struct Thing
{
	int a;
	int b;	
} Thing;

int main()
{
	int a = 1;
	int b = 1;
	while(1)
	{
		Thing* thing = malloc(sizeof(Thing));
		thing->a = a;
		thing->b = b;
		a += 1;
		b += 2;
		free(thing);
	}
}
