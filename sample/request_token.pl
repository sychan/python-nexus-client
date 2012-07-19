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


$user_id = shift @ARGV;
$keypath = shift @ARGV;
$url = shift @ARGV;

die("$keypath is unreadable") unless (-r $keypath);

$key = `cat $keypath`;
$path = "/authorize";
$method = "GET";
$user_id = "test";
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
$client = LWP::UserAgent->new(default_headers => $headers);
$client->ssl_opts(verify_hostname => 0);
$geturl = sprintf('%s%s?%s', $url,$path,$query);
$response = $client->get( $geturl);
$nexus_response = decode_json( $response->content());
print Dumper( $nexus_response);

sub sha1_base64_padded {
    $in = shift;
    $pad[0] = '';
    $pad[1] = '===';
    $pad[2] = '==';
    $pad[3] = '=';

    $out = sha1_base64( $in);
    return ($out.$pad[length($out) % 4]);
}

sub sign_with_rsa {
    %p = @_;
    $rsakey = $p{rsakey}; # actual rsa private key string in RSA or DSA format
    $path = $p{path};
    $method = $p{method};
    $user_id = $p{user_id};
    $body = $p{body} || ''; 
    $query = $p{query} || '';

    $timestamp = canonical_time(time());
    %headers = ( 'X-Nexus-UserId' => $user_id,
		 'X-Nexus-Sign'   => 'version=1.0',
		 'X-Nexus-Timestamp' => $timestamp,
	);

    $to_sign = join("\n",
		    "Method:%s",
		    "Hashed Path:%s",
		    "X-Nexus-Content-Hash:%s",
		    "X-Nexus-Query-Hash:%s",
		    "X-Nexus-Timestamp:%s",
		    "X-Nexus-UserId:%s");
    $to_sign = sprintf( $to_sign,
			$method,
			sha1_base64_padded($path),
			sha1_base64_padded($body),
			sha1_base64_padded($query),
			$timestamp,
			$headers{'X-Nexus-UserId'});
    $pkey = Crypt::OpenSSL::RSA->new_private_key($rsakey);
    $pkey->use_sha1_hash();
    $sig = $pkey->sign($to_sign);
    $sig_base64 = encode_base64( $sig);
    @sig_base64 = split( '\n', $sig_base64);
    foreach $x (0..$#sig_base64) {
	$headers{ sprintf( 'X-Nexus-Authorization-%s', $x)} = $sig_base64[$x];
    }
    return(%headers);
    
}
           
sub canonical_time {
    $time = shift;
    return( strftime("%Y-%m-%dT%H:%M:%S", localtime($time)) . 'Z');

}
