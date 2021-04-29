---
title: "Post about Write-ups"
layout: archive
permalink: /categories/writeup
author_profile: true
sidebar:
  nav: sidebar-main
---

{% assign posts = site.categories.Writeup| sort:"date" %}

{% for post in posts %}
  {% include archive-single.html type=page.entries_layout %}
{% endfor %}

