Crypto
======

.. image:: image.png
    :alt: Aplus Framework Crypto Library

Aplus Framework Crypto Library.

- `Installation`_
- `Getting Started`_
- `Box`_
- `BoxSeal`_
- `GenericHash`_
- `Password`_
- `SecretBox`_
- `Sign`_
- `Utils`_
- `Conclusion`_

Installation
------------

The installation of this library can be done with Composer:

.. code-block::

    composer require aplus/crypto

Getting Started
---------------

The Crypto library is built on top of Sodium, providing tools that simplify its
use.

Box
---

The **Box** class allows communication with encrypted messages between two
entities.

For this, both must have a public and a private key, generated by their own key
pair.

Below we generate the key pair and keys for a user:

.. code-block:: php

    use Framework\Crypto\Box;

    $user1KeyPair = Box::makeKeyPair(); // string
    $user1PublicKey = Box::makePublicKey($user1KeyPair); // string
    $user1SecretKey = Box::makeSecretKey($user1KeyPair); // string

Then we generate the key pair and another user's keys:

.. code-block:: php

    $user2KeyPair = Box::makeKeyPair(); // string
    $user2PublicKey = Box::makePublicKey($user2KeyPair); // string
    $user2SecretKey = Box::makeSecretKey($user2KeyPair); // string

Once that's done, let's create a box to encrypt messages from user 1 to user 2.

First, we create a nonce:

.. code-block:: php

    $nonce = Box::makeNonce(); // string

Next, we create the Box for user 1, using the secret key for user 1 and the
public key for user 2:

.. code-block:: php

    $user1Box = new Box($user1SecretKey, $user2PublicKey, $nonce);

So we can encrypt a message with the ``encrypt`` method:

.. code-block:: php

    $messageFromUser1 = 'What is your name?';
    $ciphertext1 = $user1Box->encrypt($messageFromUser1); // string

And it can already be decrypted by user 1, using the ``decrypt`` method:

.. code-block:: php

    $messageFromUser1 = $user1Box->decrypt($ciphertext1); // What is your name?

For the second user to be able to decrypt the message, it is necessary for him
to create an instance of Box using his secret key, the public key of user 1 and
the same nonce used in the message:

.. code-block:: php

    $user2Box = new Box($user2SecretKey, $user1PublicKey, $nonce);

With this, user 2 will be able to decrypt the ciphertext:

.. code-block:: php

    $messageFromUser1 = $user2Box->decrypt($ciphertext1); // What is your name?

To respond, user 2 can create an instance of Box, using user 1's public key:

.. code-block:: php

    $user2Box = new Box($user2SecretKey, $user1PublicKey, $nonce);

And then encrypt the message:

.. code-block:: php

    $messageFromUser2 = 'John';
    $ciphertext2 = $user2Box->encrypt($messageFromUser2); // string

Then the ciphertext can be decrypted by user 1:

.. code-block:: php

    $messageFromUser2 = $user1Box->decrypt($ciphertext2); // John

And by user 2 himself:

.. code-block:: php

    $messageFromUser2 = $user2Box->decrypt($ciphertext2); // John

BoxSeal
-------

**BoxSeal** allows you to encrypt a message so that only the recipient can
decrypt it.

First of all, the recipient needs to have a keypair that can be generated by
the ``makeKeyPair`` method:

.. code-block:: php

    use Framework\Crypto\BoxSeal;

    $keyPair = BoxSeal::makeKeyPair(); // string

Then it generates a public key with the ``makePublicKey`` method:

.. code-block:: php

    $publicKey = BoxSeal::makePublicKey($keyPair); // string

And this public key will be given to whoever will encrypt the messages.

Below is a message being encrypted:

.. code-block:: php

    $message = 'Expect Us!';
    $ciphertext = BoxSeal::encrypt($message, $publicKey); // string

Then, when the ciphertext is delivered to the recipient, he can decrypt the
message using the ``$keyPair`` with the ``decrypt`` method:

.. code-block:: php

    $message = BoxSeal::decrypt($ciphertext, $keyPair); // Expect Us!

GenericHash
-----------

The **GenericHash** class allows verifying messages through signatures.

First, you must generate a key with the ``makeKey`` method:

.. code-block:: php

    use Framework\Crypto\GenericHash;

    $key = GenericHash::makeKey(); // string

Once this is done, it is possible to generate signatures for messages. Let's
look at the following example:

.. code-block:: php

    $genericHash = new GenericHash($key);

    $message = 'Hello, friend';
    $signature = $genericHash->signature($message); // string

And then you can perform the verification:

.. code-block:: php

    if ($genericHash->verify($message, $signature)) {
        echo 'Message is verified.';
    } else {
        echo 'Error: Message is not verified.';
    }

Password
--------

With the **Password** class it is possible to generate hashes and verify
passwords.

Let's see how to generate a hash:

.. code-block:: php

    use Framework\Crypto\Password;

    $password = 'iloveyou';
    $hash = Password::hash($password); // string

The hash can be saved for future verification with the user's password, it is
97 characters long.

To verify that the password is valid, comparing it with the saved hash, you can
use the ``verify`` method:

.. code-block:: php

    Password::verify($password, $hash); // bool

If it returns ``true``, the password is correct.

The ``hash`` method has two parameters for setting `Limits`_:

.. code-block:: php

    $opslimit = Password::LIMIT_INTERACTIVE;
    $memlimit = Password::LIMIT_MODERATE;
    $hash = Password::hash($password, $opslimit, $memlimit); // string

When limits change, it may be necessary to recreate a valid hash to store.

To find out if you need to create a new hash, use the ``needsRehash`` method:

.. code-block:: php

    Password::needsRehash($hash); // bool

It also has parameters to pass the limits of operations and memory:

.. code-block:: php

    if (Password::needsRehash($hash, Password::LIMIT_MODERATE)) {
        $hash = Password::hash($password, Password::LIMIT_MODERATE);
    }

Limits
#######

The Password class has three constants that must be used to set the number of
CPU operations or memory usage.

These values can be set in the methods of the class at each call or set in
properties by the ``setOpsLimit`` and ``setMemLimit`` methods:

.. code-block:: php

    Password::setOpsLimit(Password::LIMIT_SENSITIVE); // void
    Password::setMemLimit(Password::LIMIT_MODERATE); // void

LIMIT_INTERACTIVE
"""""""""""""""""

Used to set operations or memory limit as interactive.

It enables the use of 2 CPU operations or 64 MB RAM.

LIMIT_MODERATE
""""""""""""""

Used to set operations or memory limit as moderate.

It enables the use of 3 CPU operations or 256 MB RAM.

LIMIT_SENSITIVE
"""""""""""""""

Used to set operations or memory limit as sensitive.

It enables the use of 4 CPU operations or 1 GB RAM.

SecretBox
---------

The **SecretBox** class allows you to encrypt and decrypt messages through a key
and a nonce.

First, you must have a key and a nonce. Which can be generated as in the example
below:

.. code-block:: php

    use Framework\Crypto\SecretBox;

    $key = SecretBox::makeKey(); // string
    $nonce = SecretBox::makeNonce(); // string

With these two strings it will be possible to encrypt messages and decrypt
ciphertexts.

To do this, create an instance of the SecretBox class passing the key and nonce
in the constructor:

.. code-block:: php

     $secretBox = new SecretBox($key, $nonce);

Once this is done, it is possible to encrypt messages:

.. code-block:: php

    $message = 'Hello, Sodium!';
    $ciphertext = $secretBox->encrypt($message); // string

And also decrypt:

.. code-block:: php

    $message = $secretBox->decrypt($ciphertext); // string or false

Note that the ``decrypt`` method will return ``false`` if it fails to decrypt.

Sign
----

The **Sign** class allows you to create message signatures using secret keys and
verify message authenticity using public keys.

First, you must have a key pair to generate the secret and public keys:

.. code-block:: php

    use Framework\Crypto\Sign;

    $keyPair = Sign::makeKeyPair(); // string

Then, the secret key that will be used to create the message signature is
generated:

.. code-block:: php

    $secretKey = Sign::makeSecretKey($keyPair); // string

Then the public key is generated. It is with it that the signature will be
verified:

.. code-block:: php

    $publicKey = Sign::makePublicKey($keyPair); // string

Below, we have a message and we generate a signature for it, using the same
message and also the secret key:

.. code-block:: php

    $message = 'Ai, aiaiai quiri qui uai';
    $signature = Sign::signature($message, $secretKey); // string

The message, signature and public key can be sent to the verifier, which will
use them to verify that the signature is valid:

.. code-block:: php

    if (Sign::verify($message, $signature, $publicKey)) {
        echo 'Signature is verified!';
    } else {
        echo 'Error: Signature is not verified!';
    }

Note that for this type of communication the secret key and the key pair should
be stored secretly.

Utils
-----

The **Utils** class has conversion methods resistant to side-channel attacks for
`Hexadecimal`_ and `Base64`_.

Hexadecimal
###########

It is possible to convert a binary string to hexadecimal:

.. code-block:: php

    use Framework\Crypto\Utils;

    $string = 'foo';
    $hex = Utils::bin2hex($string); // string

And also convert from hexadecimal to binary:

.. code-block:: php

    $string = Utils::hex2bin($hex); // string

Base64
######

It is possible to convert a binary string to base64:

.. code-block:: php

    use Framework\Crypto\Utils;

    $string = 'foo';
    $base64 = Utils::bin2base64($string); // string

And also convert from base64 to binary:

.. code-block:: php

    $string = Utils::base642bin($base64); // string

Conclusion
----------

Aplus Crypto Library is an easy-to-use tool for, beginners and experienced, PHP developers. 
It is perfect for communicating with encrypted data and creating secure hashes. 
The more you use it, the more you will learn.

.. note::
    Did you find something wrong? 
    Be sure to let us know about it with an
    `issue <https://github.com/aplus-framework/crypto/issues>`_. 
    Thank you!
