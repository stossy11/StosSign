//
//  codesigner.m
//  codesign
//
//  Created by samsam on 1/15/26.
//

#import "CodeSigner.h"
#import "SecCodeSignerSPI.h"
#import "SecCodeSigner.h"
#import "SecCode.h"
#import "CSCommon.h"
#import "SecCodePriv.h"
#import "SecStaticCode.h"
#import "CMSDecoder.h"
#import "CodeSigner.h"
#import <Security/Security.h>
#import <dlfcn.h>

NSArray<NSString *> *allNestedCodePathsSorted(NSString *bundlePath) {
	NSMutableArray<NSString *> *results = [NSMutableArray array];
	NSFileManager *fm = [NSFileManager defaultManager];
	
	NSURL *bundleURL = [NSURL fileURLWithPath:bundlePath];
	NSDirectoryEnumerator *enumerator = [fm enumeratorAtURL:bundleURL
								 includingPropertiesForKeys:@[NSURLIsDirectoryKey, NSURLIsPackageKey]
													options:0
											   errorHandler:nil];

	for (NSURL *fileURL in enumerator) {
		NSString *path = [fileURL path];
		NSString *filename = [path lastPathComponent];
		
		if ([filename hasPrefix:@"."]) continue;

		NSNumber *isDirectory = nil;
		[fileURL getResourceValue:&isDirectory forKey:NSURLIsDirectoryKey error:nil];
		
		NSString *extension = [[path pathExtension] lowercaseString];

		if ([isDirectory boolValue]) {
			if ([extension isEqualToString:@"app"] ||
				[extension isEqualToString:@"appex"] ||
				[extension isEqualToString:@"framework"]) {
				[results addObject:path];
			}
		} else {
			BOOL isMachO = NO;
			if ([extension isEqualToString:@"dylib"]) {
				isMachO = YES;
			} else {
				NSData *header = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
				if (header.length >= 4) {
					uint32_t magic = *(const uint32_t *)header.bytes;
					if (magic == 0xfeedface || magic == 0xcefaedfe || // 32-bit
						magic == 0xfeedfacf || magic == 0xcffaedfe || // 64-bit
						magic == 0xcafebabe || magic == 0xbebafeca) { // Universal/Fat
						isMachO = YES;
					}
				}
			}
			
			if (isMachO) {
				[results addObject:path];
			}
		}
	}

	if (![results containsObject:bundlePath]) {
		[results addObject:bundlePath];
	}

	[results sortUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
		NSUInteger countA = [[a pathComponents] count];
		NSUInteger countB = [[b pathComponents] count];
		
		if (countA > countB) return NSOrderedAscending;
		if (countA < countB) return NSOrderedDescending;
		return [a compare:b];
	}];

	return results;
}



int codesignAllNested(NSString *bundlePath,
					  const char *p12Path,
					  const char *p12Password,
					  const char *mobileProvisionPath)
{
	NSFileManager *fm = [NSFileManager defaultManager];
	
	NSString *rootExtension = [[bundlePath pathExtension] lowercaseString];
	if (mobileProvisionPath && ([rootExtension isEqualToString:@"app"] || [rootExtension isEqualToString:@"appex"])) {
		NSString *destPath = [bundlePath stringByAppendingPathComponent:@"embedded.mobileprovision"];
		[fm removeItemAtPath:destPath error:nil];
		NSError *copyError = nil;
		if (![fm copyItemAtPath:[NSString stringWithUTF8String:mobileProvisionPath]
						 toPath:destPath
						  error:&copyError]) {
			NSLog(@"Failed to copy mobileprovision to root: %@", copyError);
			return 408;
		}
	}
	
	NSArray<NSString *> *paths = allNestedCodePathsSorted(bundlePath);
	NSLog(@"Signing: %@", paths);
	for (NSString *path in paths) {
		NSLog(@"Signing: %@", path);
		
		NSString *extension = [[path pathExtension] lowercaseString];
		const char *provToUse = NULL;
		
		// Pass the mobileprovision ONLY if the current item is an app or extension
		// Frameworks and dylibs should generally NOT have entitlements applied directly from a provision
		if (mobileProvisionPath && ([extension isEqualToString:@"app"] || [extension isEqualToString:@"appex"])) {
			provToUse = mobileProvisionPath;
		}

		int status = codesign_sign_with_p12_and_mobileprovision(
			path.UTF8String,
			p12Path,
			p12Password,
			provToUse,
			YES
		);

		if (status != 0) {
			NSLog(@"Failed signing %@ with status %d", path, status);
			return status;
		}
	}
	return 0;
}


int codesign_sign_with_p12_and_mobileprovision(
	const char *appPath,
	const char *p12Path,
	const char *p12Password,
	const char * _Nullable mobileProvisionPath,
	BOOL shallow
) {
	OSStatus (*__SecCodeSignerCreate)(CFDictionaryRef, SecCSFlags, SecCodeSignerRef *) =
		dlsym(RTLD_DEFAULT, "SecCodeSignerCreate");
	OSStatus (*__SecCodeSignerAddSignatureWithErrors)(SecCodeSignerRef, SecStaticCodeRef, SecCSFlags, CFErrorRef *) =
		dlsym(RTLD_DEFAULT, "SecCodeSignerAddSignatureWithErrors");

	if (!__SecCodeSignerCreate || !__SecCodeSignerAddSignatureWithErrors) {
		NSLog(@"Failed to load private SecCodeSigner symbols");
		return 404;
	}

	NSString *filePath = [NSString stringWithUTF8String:appPath];

	NSData *p12Data = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:p12Path]];
	if (!p12Data) return 405;

	CFArrayRef items = NULL;
	NSDictionary *options = @{ (__bridge id)kSecImportExportPassphrase : [NSString stringWithUTF8String:p12Password] };
	OSStatus secStatus = SecPKCS12Import((__bridge CFDataRef)p12Data, (__bridge CFDictionaryRef)options, &items);
	if (secStatus != errSecSuccess || CFArrayGetCount(items) == 0) return 406;

	CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
	SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
	if (!identity) { CFRelease(items); return 407; }

	NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
	parameters[(__bridge NSString *)kSecCodeSignerIdentity] = (__bridge id)identity;

	if (mobileProvisionPath) {
		NSData *mpData = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:mobileProvisionPath]];
		if (mpData) {
			CMSDecoderRef decoder = NULL;
			if (CMSDecoderCreate(&decoder) == errSecSuccess &&
				CMSDecoderUpdateMessage(decoder, mpData.bytes, mpData.length) == errSecSuccess &&
				CMSDecoderFinalizeMessage(decoder) == errSecSuccess) {

				CFDataRef plistData = NULL;
				if (CMSDecoderCopyContent(decoder, &plistData) == errSecSuccess && plistData) {
					NSError *error = nil;
					NSDictionary *plist = [NSPropertyListSerialization propertyListWithData:(__bridge NSData *)plistData
																					options:NSPropertyListImmutable
																					 format:nil
																					  error:&error];
					if (plist) {
						NSDictionary *entitlements = plist[@"Entitlements"];
						if (entitlements) {
							NSData *xmlData = [NSPropertyListSerialization dataWithPropertyList:entitlements
																						   format:NSPropertyListXMLFormat_v1_0
																						  options:0
																							error:nil];
							uint32_t entitlementsData[xmlData.length + 8];
							entitlementsData[0] = OSSwapHostToBigInt32(0xFADE7171);
							entitlementsData[1] = OSSwapHostToBigInt32((uint32_t)(xmlData.length + 8));
							[xmlData getBytes:&entitlementsData[2] length:xmlData.length];

							parameters[(__bridge NSString *)kSecCodeSignerEntitlements] =
								[NSData dataWithBytes:entitlementsData length:xmlData.length + 8];
						}
					}
					CFRelease(plistData);
				}
				CFRelease(decoder);
			}
		}
	}

	NSLog(@"Signer parameters: %@", parameters);
	SecCodeSignerRef signerRef = NULL;
	SecCSFlags createFlags = 0;
	if (!shallow) {
		createFlags |= kSecCSSignNestedCode;
	}
	secStatus = __SecCodeSignerCreate((__bridge CFDictionaryRef)parameters, createFlags, &signerRef);
	if (secStatus != errSecSuccess || !signerRef) {
		NSLog(@"SecCodeSignerCreate failed! OSStatus = %d", (int)secStatus);
		CFRelease(items);
		return 201;
	}

	SecStaticCodeRef staticCode = NULL;
	secStatus = SecStaticCodeCreateWithPathAndAttributes((__bridge CFURLRef)[NSURL fileURLWithPath:filePath],
														 kSecCSDefaultFlags,
														 (__bridge CFDictionaryRef)@{},
														 &staticCode);
	if (secStatus != errSecSuccess || !staticCode) {
		NSLog(@"SecStaticCodeCreateWithPathAndAttributes failed! OSStatus = %d", (int)secStatus);
		CFRelease(signerRef);
		CFRelease(items);
		return 202;
	}

	CFErrorRef errorRef = NULL;
	secStatus = __SecCodeSignerAddSignatureWithErrors(signerRef, staticCode, kSecCSDefaultFlags, &errorRef);

	if (secStatus != errSecSuccess) {
		if (errorRef) {
			NSError *nsError = (__bridge NSError *)errorRef;
			NSLog(@"Error signing: %@ (OSStatus: %d)", nsError, (int)secStatus);
			if (nsError.userInfo) {
				for (NSString *key in nsError.userInfo) {
					NSLog(@"  %@: %@", key, nsError.userInfo[key]);
				}
			}
			CFRelease(errorRef);
		} else {
			NSLog(@"Error signing with unknown reason (OSStatus: %d)", (int)secStatus);
		}
		CFRelease(staticCode);
		CFRelease(signerRef);
		CFRelease(items);
		return 203;
	}

	CFRelease(staticCode);
	CFRelease(signerRef);
	CFRelease(items);

	return 0;
}
