#include <iostream>
//#include <stdexcept>
//#include <cstdlib>
#include <string>
#include <fstream>

void cin_test()
{
		using std::cin;
		using std::cerr;
		using std::endl;
		using std::cout;

		int ival;
		// read cin and test only for EOF; loop is executed even if there are other IO failures
		while (cin >> ival, !cin.eof()) 
		{
				if (cin.bad())         // input stream is corrupted; bail out
				{        //throw runtime_error("IO stream corrupted");
					cerr<<"bad data...";			
					break;
				}
					if (cin.fail()) 
				{		                  // bad input
					cerr<< "bad data, try again";     //warm the user
					cin.clear();//std::istream::failbit);      //reset the stream
					sleep(1);
					continue;                         //get next input
				}
				// ok to process ival
				cout<<"ival = "<<ival<<endl;				
		}

}

int main()
{
	std::fstream file("cin.cpp");
	std::string str;
	while(getline(file, str))
			std::cout<<str<<std::endl;

	file.close();
	file.clear();

	return 0;
}
