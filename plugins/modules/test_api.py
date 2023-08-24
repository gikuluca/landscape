from ansible_collections.gikuluca.landscape.plugins.module_utils.base import API, HTTPError


def main():

    api = API('https://landscape/api/', 'E713UJ2LD90N99CNX606','Pg0seTQOt3OtnW4tEsBHBRRJJ+1L4lqvDHC1bvXf','/home/giku/landscape_server_ca.crt' )
    try:
        result = api.get_computers()
    except HTTPError as e:
        print('error')
        exit(0)
    actual_computers = list(map(lambda x: x['hostname'], result))

    print(result)


if __name__ == '__main__':
    main()