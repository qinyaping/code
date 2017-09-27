#include <iostream>

int arr[] = {1,7,-4,5,2,-9,8};

int GetSum(int* arr, int n)
{
		if(arr == NULL || n < 1)
				return 1<<31;
	int max = 1<<31;
	int sum = arr[0];
	int start = 0;
	int tmp = 0;
	int end = 0;
	for(int i=1; i<n; i++)
	{
		if(	arr[i] > sum + arr[i])
		{
				sum = arr[i];
				tmp = i;
		}
		else
				sum += arr[i];
		
		if(max < sum)
		{
				start = tmp;
				end = i;
				max = sum;
		}
	}
	std::cout<<"start = "<<start<<"  end = "<<end<<std::endl;
	return max;
}

int main()
{
	int max = GetSum(arr, 7);

	std::cout<<"max = "<<max<<std::endl;
}
