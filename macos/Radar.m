#import "Radar.h"
#import "RadarLicense.h"
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
static NSString *const TAService=@"se.ibert.ThreatAtlas.RadarAlpha";
@implementation TARadar
+ (BOOL)isCurrentConsent:(NSString *)identity {return [identity isEqualToString:TA_RADAR_CONSENT];}
+ (BOOL)licenseAccepted {return [self isCurrentConsent:[self.defaults stringForKey:@"TARadarAcceptedTerms"]];}
+ (BOOL)requestLicenseAcceptance {
    if(self.licenseAccepted)return YES;
    NSAlert *alert=[NSAlert new];alert.messageText=@"Cloudflare Radar licence — acceptance required for this build";
    alert.informativeText=@"Radar data is provided by Cloudflare under Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0). Attribution is required. This licence does not authorize commercial use; obtain separate permission before commercial SOC use. Cloudflare data is separate from this project's MIT source code.\n\nTerms: https://creativecommons.org/licenses/by-nc/4.0/\nLegal code: https://creativecommons.org/licenses/by-nc/4.0/legalcode.en\nSource: https://developers.cloudflare.com/radar/\n\nAccept only if your intended use complies. Each new version/build, including RCs, requires acceptance again. Declining exits the app; screensaver displays a review-in-app notice and makes no data connections.";
    [alert addButtonWithTitle:@"Accept for this build"];[alert addButtonWithTitle:@"Decline / exit"];[alert addButtonWithTitle:@"Read legal terms"];
    NSModalResponse answer=[alert runModal];
    if(answer==NSAlertThirdButtonReturn){[NSWorkspace.sharedWorkspace openURL:[NSURL URLWithString:@"https://creativecommons.org/licenses/by-nc/4.0/legalcode.en"]];return [self requestLicenseAcceptance];}
    if(answer!=NSAlertFirstButtonReturn)return NO;
    [self.defaults setObject:TA_RADAR_CONSENT forKey:@"TARadarAcceptedTerms"];return YES;
}
+ (NSUserDefaults *)defaults {return [[NSUserDefaults alloc] initWithSuiteName:TAService];}
+ (instancetype)shared {static TARadar *r;static dispatch_once_t once;dispatch_once(&once,^{r=[TARadar new];r.status=@"Not connected — configure Radar Read token";r.outages=@[];r.traffic=@[];r.outagesStatus=@"Not loaded";r.trafficStatus=@"Not loaded";});return r;}
+ (NSDictionary *)decode:(NSData *)data error:(NSError **)error {
    id value=[NSJSONSerialization JSONObjectWithData:data options:0 error:error];
    if (![value isKindOfClass:NSDictionary.class] || ![value[@"success"] isEqual:@YES] || ![value[@"result"] isKindOfClass:NSDictionary.class]) return nil;
    return value[@"result"];
}
+ (NSArray<NSNumber *> *)trafficValues:(NSDictionary *)result {
    id series=result[@"serie_0"];if(![series isKindOfClass:NSDictionary.class])return @[];
    id raw=series[@"values"];if(![raw isKindOfClass:NSArray.class])return @[];
    id times=series[@"timestamps"];if(![times isKindOfClass:NSArray.class]||[times count]!=[raw count])return @[];
    NSMutableArray *out=[NSMutableArray new];
    for(id v in raw){if(out.count>=168)break;if(![v isKindOfClass:NSString.class]&&![v isKindOfClass:NSNumber.class])return @[];
        NSScanner *scanner=[NSScanner scannerWithString:[v description]];double n;
        if(![scanner scanDouble:&n]||!scanner.isAtEnd||!isfinite(n)||n<0)return @[];[out addObject:@(n)];}
    return out;
}
+ (NSArray<NSString *> *)outageLines:(NSDictionary *)result {
    id items=result[@"annotations"];if(![items isKindOfClass:NSArray.class])return @[];NSMutableArray *out=[NSMutableArray new];
    for(id row in items){if(out.count==5)break;if(![row isKindOfClass:NSDictionary.class])continue;
        id countries=row[@"locations"];NSString *location=@"Global";
        if([countries isKindOfClass:NSArray.class]){NSMutableArray *valid=[NSMutableArray new];for(id c in countries)if([c isKindOfClass:NSString.class])[valid addObject:c];location=[valid componentsJoinedByString:@", "];}
        NSString *start=[row[@"startDate"] isKindOfClass:NSString.class]?row[@"startDate"]:@"Time unknown";
        NSString *scope=[row[@"scope"] isKindOfClass:NSString.class]?row[@"scope"]:@"Outage";
        NSString *ended=[row[@"endDate"] isKindOfClass:NSString.class]?@"ended":@"end not reported";
        NSString *line=[NSString stringWithFormat:@"%@ · %@\n%@ · %@",location,scope,start,ended];[out addObject:[line substringToIndex:MIN(line.length,320)]];}
    return out;
}
- (NSString *)token {
    LAContext *context=[LAContext new];context.interactionNotAllowed=YES;
    CFTypeRef result=NULL;NSDictionary *query=@{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,(__bridge id)kSecAttrService:TAService,(__bridge id)kSecAttrAccount:@"RadarRead",(__bridge id)kSecReturnData:@YES,(__bridge id)kSecUseAuthenticationContext:context};
    OSStatus s=SecItemCopyMatching((__bridge CFDictionaryRef)query,&result);if(s!=errSecSuccess)return nil;
    return [[NSString alloc] initWithData:CFBridgingRelease(result) encoding:NSUTF8StringEncoding];
}
- (void)configureToken:(NSString *)token {
    NSDictionary *query=@{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,(__bridge id)kSecAttrService:TAService,(__bridge id)kSecAttrAccount:@"RadarRead"};
    OSStatus s=errSecSuccess;
    if(token.length){NSData *data=[token dataUsingEncoding:NSUTF8StringEncoding];s=SecItemUpdate((__bridge CFDictionaryRef)query,(__bridge CFDictionaryRef)@{(__bridge id)kSecValueData:data});if(s==errSecItemNotFound){NSMutableDictionary *add=[query mutableCopy];add[(__bridge id)kSecValueData]=data;add[(__bridge id)kSecAttrAccessible]=(__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;s=SecItemAdd((__bridge CFDictionaryRef)add,NULL);}}
    self.blocked=NO;self.nextFetch=nil;self.status=s==errSecSuccess?@"Ready to refresh":@"Keychain save failed; token not logged";
    if(s==errSecSuccess)[self refresh];
}
- (void)refresh {
    if(!TARadar.licenseAccepted){self.status=@"Licence acceptance required in the app for this build";return;}
    if(self.inFlight||self.blocked||(self.nextFetch&&[self.nextFetch timeIntervalSinceNow]>0))return;
    NSUserDefaults *d=TARadar.defaults;
    if(![d boolForKey:@"TARadarEnabled"]){self.status=@"Disabled";return;}
    NSString *token=[self token];if(!token.length){self.status=@"Token required — open Radar settings in the app";return;}
    self.inFlight=YES;self.status=@"Refreshing aggregated Radar data…";self.nextFetch=[NSDate dateWithTimeIntervalSinceNow:600];
    NSArray *paths=@[@"annotations/outages?dateRange=7d&limit=5&format=json",@"netflows/timeseries?dateRange=1d&aggInterval=1h&format=json"];
    __block NSUInteger pending=paths.count;__block BOOL failed=NO;
    NSURLSessionConfiguration *config=NSURLSessionConfiguration.ephemeralSessionConfiguration;config.timeoutIntervalForRequest=20;config.timeoutIntervalForResource=30;
    NSURLSession *session=[NSURLSession sessionWithConfiguration:config];
    for(NSUInteger i=0;i<paths.count;i++){
        NSMutableURLRequest *request=[NSMutableURLRequest requestWithURL:[NSURL URLWithString:[@"https://api.cloudflare.com/client/v4/radar/" stringByAppendingString:paths[i]]]];
        request.HTTPShouldHandleCookies=NO;[request setValue:[@"Bearer " stringByAppendingString:token] forHTTPHeaderField:@"Authorization"];
        [[session dataTaskWithRequest:request completionHandler:^(NSData *data,NSURLResponse *response,NSError *error){
            NSHTTPURLResponse *http=(NSHTTPURLResponse *)response;NSDictionary *result=nil;
            if(!error&&http.statusCode==200&&data.length<=2*1024*1024)result=[TARadar decode:data error:nil];
            if(i==0&&![result[@"annotations"] isKindOfClass:NSArray.class])result=nil;
            dispatch_async(dispatch_get_main_queue(),^{
                NSString *state;
                if(result){state=@"Fetched";if(i==0)self.outages=[TARadar outageLines:result];else {self.traffic=[TARadar trafficValues:result];id meta=result[@"meta"];id updated=[meta isKindOfClass:NSDictionary.class]?meta[@"lastUpdated"]:nil;self.datasetUpdated=[updated isKindOfClass:NSString.class]?updated:@"Dataset time unavailable";if(!self.traffic.count){state=@"Invalid traffic series; no graph";failed=YES;}}}
                else {failed=YES;state=[NSString stringWithFormat:@"Unavailable (HTTP %ld); retained data is stale",(long)http.statusCode];
                    if(http.statusCode==401||http.statusCode==403){self.blocked=YES;state=@"Authorization denied — update token";}
                    if(http.statusCode==429){NSTimeInterval seconds=MAX(600,[[http valueForHTTPHeaderField:@"Retry-After"] doubleValue]);self.nextFetch=[NSDate dateWithTimeIntervalSinceNow:seconds];state=@"Rate limited — retry deferred";}}
                if(i==0)self.outagesStatus=state;else self.trafficStatus=state;
                if(--pending==0){self.inFlight=NO;self.status=failed?@"Partial/unavailable — see each layer status":@"Fetched aggregates — not real-time events";if(!failed)self.fetched=NSDate.date;[session finishTasksAndInvalidate];}
            });
        }] resume];
    }
}
@end
@implementation TARadarView
- (BOOL)isFlipped{return YES;}
- (void)drawRect:(NSRect)dirty {
    TARadar *r=TARadar.shared;[[NSColor colorWithCalibratedWhite:0.07 alpha:1] setFill];NSRectFill(self.bounds);
    NSDictionary *style=@{NSForegroundColorAttributeName:NSColor.whiteColor,NSFontAttributeName:[NSFont systemFontOfSize:13]};
    NSUserDefaults *d=TARadar.defaults;
    NSString *text=[NSString stringWithFormat:@"CLOUDFLARE RADAR · MAC ALPHA\n%@\nFetch: %@\nDataset: %@\n\n%@\n\n%@\n\nSource: Cloudflare Radar • CC BY-NC 4.0\nhttps://radar.cloudflare.com/\nGlobal aggregates; not individual attack routes.\nGreyNoise remains a separate source.",(r.fetched&&-r.fetched.timeIntervalSinceNow>1200)?@"STALE — last successful fetch over 20 minutes ago":r.status,r.fetched.description?:@"Never",r.datasetUpdated?:@"Unknown",[d boolForKey:@"TARadarOutages"]?[NSString stringWithFormat:@"OUTAGES · 7 DAYS · %@\n%@",r.outagesStatus,r.outages.count?[r.outages componentsJoinedByString:@"\n\n"]:@"No outage data loaded"]:@"Outage layer hidden",[d boolForKey:@"TARadarTraffic"]?[NSString stringWithFormat:@"TRAFFIC · 24 HOURS · %@\nNormalized index; relative trend, not attack count",r.trafficStatus]:@"Traffic layer hidden"];
    [text drawInRect:NSInsetRect(self.bounds,16,16) withAttributes:style];
    if([d boolForKey:@"TARadarTraffic"]&&r.traffic.count>1&&self.bounds.size.height>650){
        NSRect graph=NSMakeRect(20,self.bounds.size.height-120,self.bounds.size.width-40,85);double max=0;for(NSNumber *n in r.traffic)max=MAX(max,n.doubleValue);
        if(max>0){NSBezierPath *line=[NSBezierPath bezierPath];for(NSUInteger i=0;i<r.traffic.count;i++){NSPoint p=NSMakePoint(graph.origin.x+i*graph.size.width/(r.traffic.count-1),NSMaxY(graph)-r.traffic[i].doubleValue/max*graph.size.height);if(i==0)[line moveToPoint:p];else [line lineToPoint:p];}[[NSColor systemTealColor] setStroke];line.lineWidth=2;[line stroke];}
    }
}
@end
