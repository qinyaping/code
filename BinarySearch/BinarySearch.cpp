#include <iostream>

template<class T>
const T BinarySearch(T* arr, int start, int end, int key)
{
		if(start > end)
				return -1;
	int mid = ((end-start)>>1) + start;
	std::cout<<"arr["<<mid<<"] = "<<arr[mid]<<std::endl;
	if(arr[mid] > key)
			return BinarySearch(arr, start, mid-1, key);
	else if(arr[mid] < key)
			return BinarySearch(arr, mid+1, end, key);
	else
	{
			return mid;
	}
}

template<class T>
const T search1(T* arr, int start, int end, int key)
{
	while(start <= end)
	{
		int mid = ((end-start)>>1) + start;
		if(arr[mid] == key)
				return mid;
		else if(arr[mid] < key)
				start = mid + 1;
		else
				end = mid-1;
	}
	return -1;
}

//从小到大排序 返回最小的结果
template<class T>
const T search2(T* arr, int start, int end, int key)
{
	int mid;
	while(start < end)
	{
		mid = ((end-start)>>1) + start;
		if(arr[mid] < key)
				start = mid + 1;
		else if(arr[mid] >= key)
				end = mid;
		std::cout<<"mid = "<<mid<<std::endl;
	}
	mid = ((end - start)>>1) + start;
	if(arr[mid] == key)
			return mid;
	else
		return -1;
}

//从小到大排序 返回最大的结果
template<class T>
const T search3(T* arr, int start, int end, int key)
{
		int mid;
	while(start < end)
	{
		mid = ((end-start)>>1) + start;
		if(arr[mid] <= key)
				start = mid;
		else if(arr[mid] > key)
				end = mid + 1;
	}
	mid = ((end - start)>>1) + start;
	if(arr[mid] == key)
			return mid;
	else
		return -1;
}

//从大到小排序 返回最大的值
template<class T>
const T search4(T* arr, int start, int end, int key)
{
	if(arr == NULL)
			return -2;
	int mid;
	while(start <= end)
	{
		mid = ((end - start)>>1) + start;
		if(arr[mid] >= key)
				start = mid;
		else if(arr[mid] < key)
				end = mid -1;
	}
	if(arr[mid] == key)
			return mid;
	else
			return -1;
}

int main()
{
	int arr[] = {1,4,4,4,4,9};
	int pos = BinarySearch<int>(arr, 0, 5, 7);
	pos = search2(arr, 0, 5, 4);
	pos = search3(arr, 0, 5, 4);
	std::cout<<"pos = "<<pos<<std::endl;

	return 0;
}

