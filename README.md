# Optimistic Fair Exchange Protocol in Java

This is a simple implementation of the OFE protocol that I did for a graduate software security course. It was not severely tested but granted me a good score :-) debug mode (-d) helps a bit to prove its robustness.

## Compiling

Use the provided ANT build file to build the application.

$> ant

This will create all class files inside the 'bin' directory.

## Using

After compiling the application, you have to generate key-pairs. To do this use the '-gk' command line argument.
The trusted third-party has to have the fixed identity 'TTP'. Suppose you want Alice to have identity 'A' and Bob to have identity 'B'. You have to do the following to create their keys:

# Beware, identities are case-sensitive!
$> ./run -gk TTP && ./run -gk A && ./run -gk B

Run the program with flag '-h' to see the set of possible options.
Bellow is a simple execution example. Assuming you already have created the key-pairs previously, do the following:

# Run at different terminals to see the execution in parallel.
$> ./run -ttp -lp 5000
$> ./run -b -bi B -lp 5001 -ta localhost:5000
$> ./run -a -ai A -bi B -ba localhost:5001 -ta localhost:5000

To enable the debug mode append flag '-d'.
