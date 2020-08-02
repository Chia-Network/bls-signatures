from hdkf import extract_expand


def ikm_to_lamport_sk(ikm: bytes, salt: bytes):
    return extract_expand(32 * 255, ikm, salt, b'')

def parent_sk_to_lamport_pk(parent_sk: PrivateKey: index: int):
    pass