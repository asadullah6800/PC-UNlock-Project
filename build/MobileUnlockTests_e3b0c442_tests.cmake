add_test([=[IPCTest.ServerClientConnectionLifecycle]=]  [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build/MobileUnlockTests.exe]==] [==[--gtest_filter=IPCTest.ServerClientConnectionLifecycle]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[IPCTest.ServerClientConnectionLifecycle]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[C:\Users\AsadU\DRIVE_0\PC unlock\PC UNlock Project\windows\tests\IPCTest.cpp:11]==]
    WORKING_DIRECTORY [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ConfigurationTest.DefaultValidation]=]  [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build/MobileUnlockTests.exe]==] [==[--gtest_filter=ConfigurationTest.DefaultValidation]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ConfigurationTest.DefaultValidation]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[C:\Users\AsadU\DRIVE_0\PC unlock\PC UNlock Project\windows\tests\ConfigurationTest.cpp:6]==]
    WORKING_DIRECTORY [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ConfigurationTest.InvalidPortValidation]=]  [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build/MobileUnlockTests.exe]==] [==[--gtest_filter=ConfigurationTest.InvalidPortValidation]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ConfigurationTest.InvalidPortValidation]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[C:\Users\AsadU\DRIVE_0\PC unlock\PC UNlock Project\windows\tests\ConfigurationTest.cpp:11]==]
    WORKING_DIRECTORY [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ConfigurationTest.InvalidTtlValidation]=]  [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build/MobileUnlockTests.exe]==] [==[--gtest_filter=ConfigurationTest.InvalidTtlValidation]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ConfigurationTest.InvalidTtlValidation]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[C:\Users\AsadU\DRIVE_0\PC unlock\PC UNlock Project\windows\tests\ConfigurationTest.cpp:17]==]
    WORKING_DIRECTORY [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolHeaderTest.ExactHeaderSize]=]  [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build/MobileUnlockTests.exe]==] [==[--gtest_filter=ProtocolHeaderTest.ExactHeaderSize]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolHeaderTest.ExactHeaderSize]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[C:\Users\AsadU\DRIVE_0\PC unlock\PC UNlock Project\windows\tests\ProtocolTest.cpp:8]==]
    WORKING_DIRECTORY [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolHeaderTest.SerializeDeserializeHeader]=]  [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build/MobileUnlockTests.exe]==] [==[--gtest_filter=ProtocolHeaderTest.SerializeDeserializeHeader]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolHeaderTest.SerializeDeserializeHeader]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[C:\Users\AsadU\DRIVE_0\PC unlock\PC UNlock Project\windows\tests\ProtocolTest.cpp:13]==]
    WORKING_DIRECTORY [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[CanonicalMessageTest.ExactSignedMessageSize]=]  [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build/MobileUnlockTests.exe]==] [==[--gtest_filter=CanonicalMessageTest.ExactSignedMessageSize]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[CanonicalMessageTest.ExactSignedMessageSize]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[C:\Users\AsadU\DRIVE_0\PC unlock\PC UNlock Project\windows\tests\ProtocolTest.cpp:41]==]
    WORKING_DIRECTORY [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[CanonicalMessageTest.SerializeDeserializeSignedMessage]=]  [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build/MobileUnlockTests.exe]==] [==[--gtest_filter=CanonicalMessageTest.SerializeDeserializeSignedMessage]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[CanonicalMessageTest.SerializeDeserializeSignedMessage]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[C:\Users\AsadU\DRIVE_0\PC unlock\PC UNlock Project\windows\tests\ProtocolTest.cpp:46]==]
    WORKING_DIRECTORY [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolValidationTest.InvalidMagicRejection]=]  [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build/MobileUnlockTests.exe]==] [==[--gtest_filter=ProtocolValidationTest.InvalidMagicRejection]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolValidationTest.InvalidMagicRejection]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[C:\Users\AsadU\DRIVE_0\PC unlock\PC UNlock Project\windows\tests\ProtocolTest.cpp:75]==]
    WORKING_DIRECTORY [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolValidationTest.InvalidVersionRejection]=]  [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build/MobileUnlockTests.exe]==] [==[--gtest_filter=ProtocolValidationTest.InvalidVersionRejection]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolValidationTest.InvalidVersionRejection]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[C:\Users\AsadU\DRIVE_0\PC unlock\PC UNlock Project\windows\tests\ProtocolTest.cpp:84]==]
    WORKING_DIRECTORY [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolValidationTest.InvalidOpcodeRejection]=]  [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build/MobileUnlockTests.exe]==] [==[--gtest_filter=ProtocolValidationTest.InvalidOpcodeRejection]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolValidationTest.InvalidOpcodeRejection]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[C:\Users\AsadU\DRIVE_0\PC unlock\PC UNlock Project\windows\tests\ProtocolTest.cpp:102]==]
    WORKING_DIRECTORY [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolValidationTest.PayloadTooLargeRejection]=]  [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build/MobileUnlockTests.exe]==] [==[--gtest_filter=ProtocolValidationTest.PayloadTooLargeRejection]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolValidationTest.PayloadTooLargeRejection]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[C:\Users\AsadU\DRIVE_0\PC unlock\PC UNlock Project\windows\tests\ProtocolTest.cpp:120]==]
    WORKING_DIRECTORY [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
add_test([=[ProtocolValidationTest.TruncatedMessageRejection]=]  [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build/MobileUnlockTests.exe]==] [==[--gtest_filter=ProtocolValidationTest.TruncatedMessageRejection]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ProtocolValidationTest.TruncatedMessageRejection]=]
  PROPERTIES
    
    DEF_SOURCE_LINE [==[C:\Users\AsadU\DRIVE_0\PC unlock\PC UNlock Project\windows\tests\ProtocolTest.cpp:132]==]
    WORKING_DIRECTORY [==[C:/Users/AsadU/DRIVE_0/PC unlock/PC UNlock Project/build]==]
    SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==]
    
)
set(MobileUnlockTests_TESTS [==[IPCTest.ServerClientConnectionLifecycle]==] [==[ConfigurationTest.DefaultValidation]==] [==[ConfigurationTest.InvalidPortValidation]==] [==[ConfigurationTest.InvalidTtlValidation]==] [==[ProtocolHeaderTest.ExactHeaderSize]==] [==[ProtocolHeaderTest.SerializeDeserializeHeader]==] [==[CanonicalMessageTest.ExactSignedMessageSize]==] [==[CanonicalMessageTest.SerializeDeserializeSignedMessage]==] [==[ProtocolValidationTest.InvalidMagicRejection]==] [==[ProtocolValidationTest.InvalidVersionRejection]==] [==[ProtocolValidationTest.InvalidOpcodeRejection]==] [==[ProtocolValidationTest.PayloadTooLargeRejection]==] [==[ProtocolValidationTest.TruncatedMessageRejection]==])
