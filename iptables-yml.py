#!/usr/bin/env python3
from collections import OrderedDict
import yaml
import iptc
import argparse
import sys
import re
__version__ = "0.0.1"

# YAMLの順番を保持する
yaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
                     lambda loader, node: OrderedDict(loader.construct_pairs(node)))

def options():
    parser = argparse.ArgumentParser(prog='iptables-yml.py',
                                     add_help=True,
                                     description='YAMLでiptablesの設定をするツール')
    sub_parser = parser.add_subparsers()

    # init sub command.
    parser_init = sub_parser.add_parser('init',
                                        help='設定を初期化して設定を入れ直す')
    parser_init.add_argument('-f', '--file',
                             type=str,
                             help='YAMLファイルを指定')
    parser_init.set_defaults(handler=init)

    # reset sub command.
    parser_reset = sub_parser.add_parser('reset',
                                         help='設定をリセットする')
    parser_reset.set_defaults(handler=reset)

    args = parser.parse_args()
    if hasattr(args, 'handler'):
        args.handler(args)
    else:
        parser.print_help()
        sys.exit(1)

    return args

def yaml_parse(file):
    """
    YAMLをパースする

    :type file: str
    :param file: YAMLが記述されているファイル

    :rtype: dict
    :return: YAMLをパースした辞書
    """
    try:
        with open(file, 'r') as f:
            configs = yaml.load(f)
    except:
        print("YAMLのパース処理失敗...")
        sys.exit(1)

    return configs

def chains_reset(table):
    """
    全てのChainをリセットする

    :type table: class
    :param table: iptc.ip4tc.Table
    """
    for chain in (table.chains):
        # chainのflush
        chain.flush()
        # 初期チェーン以外は削除
        if(not(re.match(r"INPUT|FORWARD|OUTPUT", chain.name))):
            chain.delete()
        else:
            # 初期チェーンは全て `ACCEPT` へ変更
            chain.set_policy("ACCEPT")

def chains_policy_drop():
    """
    INPUT/FORWARD/OUTPUTのポリシーをDROPにする
    """
    drop_chains = ["INPUT", "FORWARD", "OUTPUT"]
    for chain in drop_chains: iptc.Chain(iptc.Table('filter'), chain).set_policy("DROP")

def reset(args):
    """
    iptablesの設定を初期化する

    :type args: class
    :param args: argparse.Namespace
    """
    # Chainを初期化
    table = iptc.Table('filter')
    chains_reset(table)

def init(args):
    """
    一旦iptables設定を初期化し、YAMLで書かれているiptablesの設定を元にて再度設定し直す

    :type args: class
    :param args: argparse.Namespace
    """
    # YAMLパース
    configs = yaml_parse(args.file)

    # Chainを初期化
    table = iptc.Table('filter')
    chains_reset(table)

    # iptables設定
    for key1 in configs.keys():
        for key2 in configs[key1].keys():
            rule = iptc.Rule()
            chain = iptc.Chain(iptc.Table('filter'), key2)
            rules = configs[key1][key2]
            for key3 in rules.keys():
                # Rule設定
                if(key3 == 'target'):
                    rule.target = iptc.Target(rule, configs[key1][key2][key3].upper())
                else:
                    setattr(rule, key3, rules[key3])

            # protocol options.
            if('protocol_options' in rules):
                for option in rules['protocol_options'].keys():
                    if(option == "protocol"):
                        setattr(rule, option, str(rules['protocol_options'][option]))
                    else:
                        setattr(rule.create_match(rules['protocol_options']['protocol']), option, str(rules['protocol_options'][option]))

            # コメント設定
            match_comment = iptc.Match(rule, "comment")
            match_comment.comment = key1
            rule.add_match(match_comment)

            # ChainにRuleを入れる
            chain.append_rule(rule)

    # INPUT/FORWARD/OUTPUTのポリシーをDROPにする
    chains_policy_drop()

if __name__ == "__main__":
    args = options()
