#!/usr/local/bin/perl
use strict;
use Net::Pcap;
use Net::Frame::Device;
use Net::Netmask;
use Data::Dumper;
################Declarations################################
my ($err,$dev,$dev_info,$my_ip,$my_mac,$subnet);
$err="";
############################################################
$dev=pcap_lookupdev(\$err);
#print Dumper $dev;
$dev_info= Net::Frame::Device->new(dev => "$dev");
$my_ip=$dev_info->ip;
$my_mac=$dev_info->mac;
$subnet=$dev_info->subnet;
print Dumper $subnet;
