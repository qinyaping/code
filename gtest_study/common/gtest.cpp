#include "gtest.h"

UnitTest* UnitTest::GetInstance()
{
    static UnitTest instance;
    return &instance;
}

TestCase* UnitTest::RegisterTestCase(TestCase* testcase)
{
    testcases_.push_back(testcase);
    return testcase;
}

int UnitTest::Run()
{
    nTestResult = 1;
    for (std::vector<TestCase*>::iterator it = testcases_.begin();
        it != testcases_.end(); ++it)
    {
        TestCase* testcase = *it;
        CurrentTestCase = testcase;
        std::cout << green << "======================================" << std::endl;
        std::cout << green << "Run TestCase:" << testcase->testcase_name << std::endl;
        testcase->Run();
        std::cout << green << "End TestCase:" << testcase->testcase_name << std::endl;
        if (testcase->nTestResult)
        {
            nPassed++;
        }
        else
        {
            nFailed++;
            nTestResult = 0;
        }
    }

    std::cout << green << "======================================" << std::endl;
    std::cout << green << "Total TestCase : " << nPassed + nFailed << std::endl;
    std::cout << green << "Passed : " << nPassed << std::endl;
    std::cout << red << "Failed : " << nFailed << std::endl;
    return nTestResult;
}

