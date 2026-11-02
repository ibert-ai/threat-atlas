#import "Radar.h"
#import "RadarLicense.h"
static void check(BOOL value, NSString *name){if(!value){NSLog(@"FAILED: %@",name);exit(1);}}
int main(){@autoreleasepool {
    NSData *d=[@"{\"success\":true,\"result\":{\"annotations\":[]}}" dataUsingEncoding:NSUTF8StringEncoding];
    check([TARadar decode:d error:nil]!=nil,@"valid envelope");
    check([TARadar decode:[@"[]" dataUsingEncoding:NSUTF8StringEncoding] error:nil]==nil,@"reject bad envelope");
    check([TARadar trafficValues:@{@"serie_0":@{@"values":@[@"1.5",@2],@"timestamps":@[@"a",@"b"]}}].count==2,@"numeric series");
    check([TARadar trafficValues:@{@"serie_0":@{@"values":@[@"NaN"],@"timestamps":@[@"a"]}}].count==0,@"reject nonfinite");
    check([TARadar trafficValues:@{@"serie_0":@{@"values":@[@1],@"timestamps":@[]}}].count==0,@"reject cardinality mismatch");
    check([TARadar outageLines:@{@"annotations":@[@{@"locations":@[@"SE"],@"startDate":@"2026-11-02T00:00:00Z",@"endDate":NSNull.null,@"scope":@"Regional"}] }].count==1,@"outage null end");
    check([TARadar outageLines:@{@"annotations":@[@1,NSNull.null]}].count==0,@"ignore invalid rows");
    check(![TARadar isCurrentConsent:nil],@"first launch requires consent");
    check(![TARadar isCurrentConsent:@"older-version-or-terms"],@"old consent invalidated");
    check([TARadar isCurrentConsent:TA_RADAR_CONSENT],@"exact build and terms match");
    puts("Radar parser/consent fixtures PASS (10 assertions); synthetic data, no live API used");
}return 0;}
