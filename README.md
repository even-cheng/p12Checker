# p12Checker
提取p12内容，检查p12状态

改接口只是检查P12状态，获取P12内容逻辑如下：
```
导入头文件
#include "pkcs12.h"
#include "p12checker.h"
```

```
- (void)readP12:(NSString *)p12_path pwd:(NSString *)pwd {
    
    PKCS12 *p12 = NULL;
    X509* usrCert = NULL;
    EVP_PKEY* pkey = NULL;
    STACK_OF(X509)* ca = NULL;
    char* password = (char*)[pwd cStringUsingEncoding:NSUTF8StringEncoding];

    BIO*bio = NULL;
    char* p = NULL;
    
    bio = BIO_new_file([p12_path UTF8String], "r");
    p12 = d2i_PKCS12_bio(bio, NULL); //得到p12结构
    BIO_free_all(bio);
    PKCS12_parse(p12, password, &pkey, &usrCert, &ca); //得到x509结构
    if (usrCert)
    {
        fprintf(stdout, "Subject:");
        p = X509_NAME_oneline(X509_get_subject_name(usrCert), NULL, 0);

        //读取证书内容
        NSDictionary* subject = [self readSubjectFormX509:p];
        NSString* country = subject[@"U"];
        NSString* name = subject[@"CN"];
        NSString* organization = subject[@"O"];
        NSString* organization_unit = subject[@"OU"];
        NSString* user_ID = subject[@"UID"];
        NSString* country = subject[@"C"];


        ASN1_TIME* before = X509_get_notBefore(usrCert);
        long start_time = [self readRealTimeForX509:(char *)before->data];

        ASN1_TIME* after = X509_get_notAfter(usrCert);
        long expire_time = [self readRealTimeForX509:(char *)after->data];

        dispatch_async(dispatch_get_global_queue(0, 0), ^{
            //9月之后苹果新增G3类型的根证书，这里需要区分
            bool g3 = [self isG3ForX509:usrCert];
            bool revoked = isP12Revoked(usrCert, g3);
        });
}
```

```
- (long )readRealTimeForX509:(char *)x509data{
    
    NSString* x509TimeString = [NSString stringWithUTF8String:x509data];
    if (x509TimeString.length<12) {
        return 0;
    }
    NSString* start_time = [NSString stringWithFormat:@"20%@-%@-%@ %@:%@:%@",[x509TimeString substringWithRange:NSMakeRange(0, 2)], [x509TimeString substringWithRange:NSMakeRange(2, 2)], [x509TimeString substringWithRange:NSMakeRange(4, 2)], [x509TimeString substringWithRange:NSMakeRange(6, 2)], [x509TimeString substringWithRange:NSMakeRange(8, 2)], [x509TimeString substringWithRange:NSMakeRange(10, 2)]];
    long timeLong = [NSDate getDateLongWithDateStr:start_time];
    return timeLong+8*60*60;
}
```

```
- (NSDictionary *)readSubjectFormX509:(char *)x509data{
    
    NSMutableDictionary* mdic = [NSMutableDictionary dictionary];
    NSString* x509String = [NSString stringWithUTF8String:x509data];
    NSArray* objs = [x509String componentsSeparatedByString:@"/"];
    for (NSString* obj in objs) {
        NSArray* content = [obj componentsSeparatedByString:@"="];
        if (content.count == 2) {
            NSDictionary* dic = @{content.firstObject:content.lastObject};
            [mdic addEntriesFromDictionary:dic];
        }
    }
    return mdic.copy;
}
```

```
- (bool)isG3ForX509:(X509*)usrCert{

    X509_NAME* name = X509_get_issuer_name(usrCert);
    const unsigned char* der = NULL;
    size_t leng;
    X509_NAME_get0_der(name, &der, &leng);
    const X509_NAME_ENTRY *ne = X509_NAME_get_entry(name, 2);
    ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(ne);
    ASN1_STRING *asn1_data = X509_NAME_ENTRY_get_data(ne);
    bool g3 = strcmp((char *)asn1_data->data, "G3") == 0; //Apple Worldwide Developer Relations
    
    return g3;
}
```
博客地址：
https://www.jianshu.com/p/31987f448e5f
