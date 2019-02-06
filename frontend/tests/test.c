#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

typedef struct Data
{
	int a;
	int b;
} Data;

int main()
{
	int a = 1;
	int b = 1;
	while(1)
	{
		sleep(3);
		Data* data = malloc(sizeof(Data));
		data->a = a;
		data->b = b;
		printf("%d %d\n", data->a, data->b);
		a++;
		b += 2;
	}
}
