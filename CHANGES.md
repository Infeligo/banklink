# The list of changes since fork

- Removed example project because it was outdated, had missing files and showed a different,
  less cleaner approach than the project offers.

- Removed LT and LV modules in order to focus on Estonian (and generic) banklink specs. 

- Removed Eclipse IDE files from the project.

- Removed `Version` holder class. 

- Removed code related to sending packet via HTTP(S). While this is necessary functionality, it really
  should be implemented in another place and actual HTTP call should be handled by a pluggable client
  like Apache HTTP client or RestTemplate. 

- Replaced `Enumeration` occurrences with `List`.
