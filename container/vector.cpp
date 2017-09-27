#include <iostream>
#include <vector>

template <typename T>
void printv(std::vector<T>& v)
{
	typename std::vector<T>::iterator iter = v.begin();
	for(;iter != v.end(); iter++)
			std::cout<<*iter<<" ";
	std::cout<<std::endl;
}

int main()
{
		using std::vector;

		vector<int> v(5, 1);

		vector<int>::iterator first = v.begin(),
				last = v.end(); // cache end iterator
/*		// diaster: behavior of this loop is undefined
		while (first != v.end()) {
				// do some processing
				// insert new value and reassign first, which otherwise would be invalid
				first = v.insert(first, 42);
				printv(v);
				sleep(1);
				++first;  // advance first just past the element we added
		}
*/
		v.back() = 2;
		printv(v);

		vector<int> tmp;
		v = tmp;
		printv(v);
		return 0;
}
