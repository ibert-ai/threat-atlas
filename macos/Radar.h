#import <Cocoa/Cocoa.h>
@interface TARadar : NSObject
@property(nonatomic, copy) NSString *status;
@property(nonatomic, copy) NSString *outagesStatus;
@property(nonatomic, copy) NSString *trafficStatus;
@property(nonatomic, copy) NSArray<NSString *> *outages;
@property(nonatomic, copy) NSArray<NSNumber *> *traffic;
@property(nonatomic, copy) NSString *datasetUpdated;
@property(nonatomic, strong) NSDate *fetched;
@property(nonatomic) BOOL inFlight;
@property(nonatomic) BOOL blocked;
@property(nonatomic, strong) NSDate *nextFetch;
+ (instancetype)shared;
+ (NSUserDefaults *)defaults;
+ (BOOL)licenseAccepted;
+ (BOOL)isCurrentConsent:(NSString *)identity;
+ (BOOL)requestLicenseAcceptance;
+ (NSDictionary *)decode:(NSData *)data error:(NSError **)error;
+ (NSArray<NSNumber *> *)trafficValues:(NSDictionary *)result;
+ (NSArray<NSString *> *)outageLines:(NSDictionary *)result;
- (void)refresh;
- (void)configureToken:(NSString *)token;
@end
@interface TARadarView : NSView
@end
