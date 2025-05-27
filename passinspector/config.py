import os

NEO4J_URI = os.getenv('PASSINSPECTOR_NEO4J_URI', 'neo4j://localhost')
NEO4J_USERNAME = os.getenv('PASSINSPECTOR_NEO4J_USERNAME', 'neo4j')
NEO4J_PASSWORD = os.getenv('PASSINSPECTOR_NEO4J_PASSWORD', 'bloodhoundcommunityedition')
