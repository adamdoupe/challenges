# pwn.college

Set of pre-generated pwn.college challenges!

## Setup

Replace `<INSTANCE>` with your instance's name:

```bash
./generate_sql.sh | docker exec -i <INSTANCE>_db mysql -uctfd -pctfd -Dctfd
```

### Warning

Currently there is an issue where docker image names can only be 32 bytes long in the pwn.college infastructure.
To remedy this:

```bash
docker tag pwncollege/pwncollege_challenge pwncollege_challenge
docker tag pwncollege/pwncollege_kernel_challenge pwncollege_kernel_challenge
```
