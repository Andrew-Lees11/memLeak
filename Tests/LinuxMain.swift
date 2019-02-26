import XCTest

import memLeakTests

var tests = [XCTestCaseEntry]()
tests += memLeakTests.allTests()
XCTMain(tests)