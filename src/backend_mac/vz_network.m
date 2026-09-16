#import "vz_network.h"

@implementation VzNetwork

+ (VZVirtioNetworkDeviceConfiguration *)natConfigurationWithMACAddress:(VZMACAddress *)macAddress {
    VZVirtioNetworkDeviceConfiguration *net = [[VZVirtioNetworkDeviceConfiguration alloc] init];
    net.MACAddress = macAddress;
    net.attachment = [[VZNATNetworkDeviceAttachment alloc] init];
    return net;
}

+ (VZVirtioNetworkDeviceConfiguration *)bridgedConfigurationForInterface:(NSString *)interfaceName
                                                            MACAddress:(VZMACAddress *)macAddress {
    NSArray<VZBridgedNetworkInterface *> *interfaces = [VZBridgedNetworkInterface networkInterfaces];
    VZBridgedNetworkInterface *chosen = nil;
    if (interfaceName.length > 0) {
        for (VZBridgedNetworkInterface *iface in interfaces) {
            if ([iface.identifier isEqualToString:interfaceName]) {
                chosen = iface;
                break;
            }
        }
    } else {
        chosen = interfaces.firstObject;
    }
    if (!chosen) return nil;

    VZVirtioNetworkDeviceConfiguration *net = [[VZVirtioNetworkDeviceConfiguration alloc] init];
    net.MACAddress = macAddress;
    net.attachment = [[VZBridgedNetworkDeviceAttachment alloc] initWithInterface:chosen];
    return net;
}

@end
