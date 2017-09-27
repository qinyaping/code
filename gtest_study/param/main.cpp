#include "gtest/gtest.h"

#define INT_MIN -1000

bool IsPrime(int n) 
{
	return false;
}
class IsPrimeParamTest : public::testing::TestWithParam<int>
{
 public:
  static void SetUpTestCase() {
    shared_resource_ = new Test1();
  }
  static void TearDownTestCase() {
    if(shared_resource_) delete shared_resource_;
    shared_resource_ = NULL;
  }
  
  // Some expensive resource shared by all tests.
  static Test1* shared_resource_;
  static int num;
	
};

//GetParam()方法用于获取当前参数的具体值
TEST_P(IsPrimeParamTest, Negative)
{
    int n =  GetParam();
    EXPECT_FALSE(IsPrime(n));
}

//INSTANTIATE_TEST_CASE_P()告知Gtest我们的被测参数都有哪些
//第一个参数为测试实例的前缀，可以随意取；第二个参数为测试类的名称；第三个参数指示被测参数
INSTANTIATE_TEST_CASE_P(NegativeTest, IsPrimeParamTest, testing::Values(-1,-2,-5,-100,INT_MIN));


int main(int argc, char* argv[])
{
	testing::InitGoogleTest(&argc, argv);
        return RUN_ALL_TESTS();
	
	return 0;
}
