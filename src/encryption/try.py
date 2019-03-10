#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2018 weirdo <weirdo@hack-box>
#
# Distributed under terms of the MIT license.

"""

"""
with open("sample_text.txt", "r") as fh:
    content = fh.readlines()

wh = open("sample_text2.txt", "a")
i = 0
while i < 1978:
    concat = ""
    for j in range(1,11):
        concat = concat + content[i + j]
    wh.writeline(concat)
    i = i+10

#content_list.append(content)

#print(content_list)
# with open("sample_text2.txt", "a") as wh:
# ...         wh.writelines(content)
