#include <iostream>

//冒泡 n-1 +  n-2 + ... + 1 = n(n-1)
template<class T>
void BubbleSort(T* arr, unsigned int n)
{
	if(arr == NULL) return;
	for(unsigned i=0; i<n; i++)
	{
		for(unsigned j=i+1; j<n; j++)
		{
			if(arr[i] > arr[j])
			{
				std::swap(arr[i], arr[j]);
			}
		}
	}
}

//选择 n-1 + n-2 + n-3 + ... + 1 = n(n-1)
template<class T>
void SelectSort(T* arr, unsigned n)
{
	if(arr == NULL) return;
	for(unsigned i=0; i<n; i++)
	{
		unsigned index = i;
		for(unsigned j=i+1; j<n; j++)
		{
			if(arr[index] > arr[j])
					index = j;
		}
		if(index != i)
		{
				std::swap(arr[index], arr[i]);
		}
	}
}

//插入 1 + 2 + ... + n-1 = n(n-1)
template<class T>
void InsertSort(T* arr, unsigned n)
{
	for(int i=0; i<n-1; i++)
	{
		int tmp = arr[i+1];
		int j;
		for(j=i+1; j>0; j--)
		{
			if(tmp >= arr[j-1])
			{
				break;
			}
			if(tmp < arr[j-1])
			{
				arr[j] = arr[j-1];
			}
		}
		arr[j] = tmp;
	}
}

//快排  3 4 2 5 3
template<class T>
void quick_sort(T* arr, int left, int right)
{
	if(left >= right)
			return ;
	int low = left;
	int high = right;
	int pv = arr[left];

	while(low < high)
	{
			while(low < high && arr[high] >= pv)
					high--;
			arr[low] = arr[high];
			while(low < high && arr[low] <= pv)
					low++;
			arr[high] = arr[low];
	}
	arr[low] = pv;
	
	quick_sort(arr, left, low-1);
	quick_sort(arr, low+1, right);

}

//堆排序
template <class T>
void MaxHeapDown(T* arr, int i, int n)
{
	if(arr == NULL || n < 1)
			return;
	if(2*i + 1 >= n)
			return;
	int j = 2*i + 1;
	if(j+1 < n && arr[j] < arr[j+1])
	{
		j += 1;
	}
	if(arr[i] > arr[j])
			return ;
	std::swap(arr[i], arr[j]);

	i = j;
	MaxHeapDown(arr, i, n);
}

template <class T>
void InitMaxHeap(T* arr, int n)
{
	for(int i=n/2 -1; i>=0; i--)
	{
		MaxHeapDown(arr, i, n);
	}
}

template <class T>
void HeapSort(T* arr, int n)
{
	InitMaxHeap(arr, n);
	for(int i=n-1; i>0; i--)
	{
		std::swap(arr[0], arr[i]);
		MaxHeapDown(arr, 0, i);
	}
}

template<class T>
void Wash(T* arr, unsigned n)
{
	if(arr == NULL) return;
	for(int i=n-1; i>=0; i--)
	{
		int num = rand()%n;
		std::swap(arr[num], arr[i]);
	}
}

template<class T>
void print(T* arr, unsigned n)
{
	for(unsigned i=0; i<n; i++)
			std::cout<<arr[i]<<"  ";
	std::cout<<std::endl;
}

int main()
{
	int arr[] = {1,4,2,3,9,0};
	BubbleSort<int>(arr, 6);
	Wash(arr, 6);
	SelectSort<int>(arr, 6);
	Wash(arr, 6);
	InsertSort<int>(arr, 6);
	Wash(arr, 6);
	quick_sort(arr, 0, 5);
	Wash(arr, 6);
	HeapSort<int>(arr, 6);
	print(arr, 6);
	return 0;
}
