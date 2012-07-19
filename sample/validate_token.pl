#
# Perl script that takes 1 argument
# a string containing a token that needs to be validated
#
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::X509;
use JSON;
use LWP::UserAgent;

$token = shift @ARGV;

($sig_data) = $token =~ /^(.*)\|sig=/;
%vars = map { split /=/ } split /\|/, $token;
$binary_sig = pack('H*',$vars{'sig'});

$client = LWP::UserAgent->new();
$client->ssl_opts(verify_hostname => 0);
$response = $client->get( $vars{'SigningSubject'});

$data = from_json( $response->content());

$rsa = Crypt::OpenSSL::RSA->new_public_key( $data->{'pubkey'});
$rsa->use_sha1_hash();

$verify1 = $rsa->verify($sig_data,$binary_sig);

print "The cleartext is $sig_data\n";
print "The signature is $sig";
print "The public key for the signing subject is:\n" . $data->{'pubkey'};
printf "The results of RSA SHA1 verification are: %s\n", $verify1 ? "True" : "False";
