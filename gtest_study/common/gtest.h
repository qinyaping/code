class TestCase
{
public:
    TestCase(const char* case_name) : testcase_name(case_name){}

    // 执行测试案例的方法
    virtual void Run() = 0;

    int nTestResult; // 测试案例的执行结果 
    
    const char* testcase_name; // 测试案例名称
};


class UnitTest
{
public:
    // 获取单例
    static UnitTest* GetInstance(); 

    // 注册测试案例
    TestCase* RegisterTestCase(TestCase* testcase);
    
    // 执行单元测试
    int Run();

    TestCase* CurrentTestCase; 		// 记录当前执行的测试案例
    int nTestResult; 				// 总的执行结果
    int nPassed; 					// 通过案例数
    int nFailed; 					// 失败案例数
protected:
    std::vector<TestCase*> testcases_; // 案例集合
};

