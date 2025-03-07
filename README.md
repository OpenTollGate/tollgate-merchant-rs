# About

## How to use

The service will be running in port 5122.

This supports nip61 version of cashu payment redemption by the receiver.

The tollgate-merchant will publish the relay that it uses and the mint that it trusts using
nutzap_info_event as defined in nip61.

The sender(tollgate-app) has to follow the logic given in `make_payment` function, it also adds an additional
"d" tag where it includes is mac_address.

The app notifies the merchant of the payment through the single endpoint `notify_payment`, by providing
it's mac address.

##TODO

Now the merchant has to add the corresponding session for that mac address.
