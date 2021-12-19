# rulebook


Answers


1. How do you map the network rules to each platform i.e. how are the rules applied on each platform and to what types of resources on that platform?

A. Did mapped them as an Object , and read the rule from a file.

2. What are the differences between the platforms from a networking perspective?

Each cloud provider has their own namning convention or API calls with diffrent arguments

3. How does this impact your ability to create an abstraction across the platforms?

Adjustments needs to be done n order deploy to multiple platforms.
Naming conventions
Diffrent API calls
Diffrent authentication methods
Need to be careful to updates of the APi that each platform does make.


4. How fine grained do you provide control over network flow?
How would you go about extending this for finer grain control?  Per instance? Per group? Per network?

Depends on what flows are implemented. I would stay maximum on groups and not manage per instance.
I whould use managment per instance only for tests , for anything else groups and network
