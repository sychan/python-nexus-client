#!/usr/bin/env perl
# 
# Perl script that takes 3 arguments
# a string containing a userid to identify yourself with
# a file path to the openssh private key to authenticate the user with
# a URL to post the request to
#

use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::X509;
use JSON;
use LWP::UserAgent;
use MIME::Base64;
use Digest::SHA1 qw(sha1_base64);
use Data::Dumper;
use URI;
use URI::QueryParam;
use POSIX;

$Data::Dumper::Sortkeys = 1;

$user_id = shift @ARGV;
$keypath = shift @ARGV;
$url = shift @ARGV;

die("$keypath is unreadable") unless (-r $keypath);

$key = `cat $keypath`;
$path = "goauth/authorize";
$method = "GET";
$u = URI->new($url);
%qparams = ("response_type" => "code",
	    "client_id" => $user_id);
$u->query_form( %qparams );
$query=$u->query();

%p = ( rsakey => $key,
       path => $path,
       method => $method,
       user_id => $user_id,
       query => $query);

%headers = sign_with_rsa( %p);
$headers = HTTP::Headers->new( %headers);
print "Headers:\n".Dumper( $headers );
$client = LWP::UserAgent->new(default_headers => $headers);
$client->ssl_opts(verify_hostname => 0);
$geturl = sprintf('%s%s?%s', $url,$path,$query);
print "URL to fetch: " . Dumper( $geturl );
$response = $client->get( $geturl);
print "Response: ".$response->content();
$nexus_response = decode_json( $response->content());
print Dumper( $nexus_response);

sub sha1_base64_padded {
    $in = shift;
    @pad = ('','===','==','=');

    $out = sha1_base64( $in);
    return ($out.$pad[length($out) % 4]);
}

sub sign_with_rsa {
    %p = @_;

    $timestamp = canonical_time(time());
    %headers = ( 'X-Globus-UserId' => $p{user_id},
		 'X-Globus-Sign'   => 'version=1.0',
		 'X-Globus-Timestamp' => $timestamp,
	);

    $to_sign = join("\n",
		    "Method:%s",
		    "Hashed Path:%s",
		    "X-Globus-Content-Hash:%s",
		    "X-Globus-Query-Hash:%s",
		    "X-Globus-Timestamp:%s",
		    "X-Globus-UserId:%s");
    $to_sign = sprintf( $to_sign,
			$p{method},
			sha1_base64_padded($p{path}),
			sha1_base64_padded($p{body}),
			sha1_base64_padded($p{query}),
			$timestamp,
			$headers{'X-Globus-UserId'});
    $pkey = Crypt::OpenSSL::RSA->new_private_key($p{rsakey});
    $pkey->use_sha1_hash();
    $sig = $pkey->sign($to_sign);
    $sig_base64 = encode_base64( $sig);
    @sig_base64 = split( '\n', $sig_base64);
    foreach $x (0..$#sig_base64) {
	$headers{ sprintf( 'X-Globus-Authorization-%s', $x)} = $sig_base64[$x];
    }
    return(%headers);
    
}
           
sub canonical_time {
    $time = shift;
    return( strftime("%Y-%m-%dT%H:%M:%S", localtime($time)) . 'Z');

}

