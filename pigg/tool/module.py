import sys
import os

from monoliths import monoliths

def exclude_pigg_imports(content):
    # Remove PIGG import statements.
    (lines, lines_out, i) = (content.split("\n"), [], 0)
    while i < len(lines):
        if lines[i] == "try:" and i+1 < len(lines) and lines[i+1].startswith("    from"):
            i += 1
            while lines[i] == "except:" or lines[i].startswith("    from"):
                i += 1
        else:
            lines_out.append(lines[i])
            i += 1

    return "\n".join(lines_out)

if __name__ == '__main__':
    # Determine which kind of merged module we are assembling.
    if len(sys.argv) < 2:
        raise ValueError("must specify at least one merged module name")

    # Destination directory for merged modules.
    destination = '../module/'

    # Different combinations of common modules used in across different merged
    # modules: data structures, cryptographic primitives, and CIGG API wrapper.
    common_data = monoliths(
        paths=[
            '../pigg/data/circuits.py',
            '../pigg/data/label.py',
            '../pigg/data/assignment.py',
            '../pigg/data/payload.py'
        ], 
        requirements=['bfcl==0.2.0', 'bitlist==0.3.1']
    )
    common_crypto_native = monoliths(
        paths=['../pigg/crypto/simple.py', '../pigg/crypto/ot.py'],
        requirements=['pynacl==1.4.0', 'oblivious==0.1.0']
    )
    common_cigg = monoliths(
        paths=['../pigg/core/cigg.py', '../pigg/crypto/comm_cigg.py'],
        requirements=['parts==0.2.1', 'canaries==0.2.0']
    )
    common_native_or_cigg = common_data + common_crypto_native + common_cigg
    common_cigg_only = common_data + common_cigg

    # Additional optional common modules and module extensions.
    hugg = monoliths(
        paths=['../pigg/ext/hugg.py'],
        requirements=['bitlist==0.3.1']
    )
    huggs = monoliths(
        paths=['../pigg/ext/huggs.py']
    )
    hush = monoliths(
        paths=['../pigg/crypto/hush.py'],
        requirements=['pynacl==1.4.0', 'ge25519==0.1.1']
    )
    hushc = monoliths(
        paths=['../pigg/ext/hushc.py'],
        requirements=['bitlist==0.3.1']
    )
    hushs = monoliths(
        paths=['../pigg/ext/hushs.py']
    )

    # Server and client functionalities.
    server_cigg_only_no_flask = monoliths(
        paths=[ '../pigg/core/server.py'], 
        requirements=['parts==0.2.1', 'bitlist==0.3.1', 'bfcl==0.2.0']
    )
    server = monoliths(
        paths=['../pigg/core/garble.py', '../pigg/core/server.py'],
        requirements=['parts==0.2.1', 'bitlist==0.3.1', 'bfcl==0.2.0', 'flask==1.1.2']
    )
    client_cigg_only = monoliths(
        paths=['../pigg/core/client.py'],
        requirements=['bitlist==0.3.1', 'requests==2.24.0']
    )
    client = monoliths(
        paths=['../pigg/core/evaluate.py'],
        requirements=['bfcl==0.2.0']
    ) + client_cigg_only

    # Circuit embeddings.
    embedded = monoliths([
        '../circuit/embedded/aes-128-ecb-encrypt.py',
        '../circuit/embedded/aes-128-ecb-decrypt.py',
        '../circuit/embedded/sha-256-for-lteq-440-bits.py',
        '../circuit/embedded/sha-256-for-lteq-952-bits.py'
    ])

    # Module that preloads circuits at the time of import.
    preload = monoliths([
        '../pigg/data/preload.py'
    ])

    # Create the destination directory if it does not exist.
    if not os.path.isdir(destination):
        os.mkdir(destination)

    # Merged module definitions.
    modules = {
        'pigg': common_native_or_cigg + server + client + preload,
        'hugg': common_native_or_cigg + embedded + client + hugg + preload,
        'huggs': common_native_or_cigg + embedded + server + huggs + preload,
        'lambda_huggs': common_cigg_only + server_cigg_only_no_flask + huggs,
        'hugg_hushc': common_native_or_cigg + hush + embedded + client + hugg + preload,
        'huggs_hushs': common_native_or_cigg + hush + embedded + server + huggs + preload
    }

    # Build each consolidated module specified in the supplied arguments.
    for module_name in sys.argv[1:]:
        if module_name in modules:
            # Transform the modules, concatenate the transformed versions,
            # and emit the single module file.
            module_path = destination + module_name + '.py'
            modules[module_name].emit(module_path, transform_str=exclude_pigg_imports)
            print("Built consolidated module at `" + module_path + "`.")
        else:
            raise ValueError("no definition for merged module '" + module_name + "'")
